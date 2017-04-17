using InsideIAM.Yubico.Library;
using Microsoft.IdentityServer.Web.Authentication.External;
using System.Collections.Generic;
using System.Configuration;
using System.DirectoryServices;
using System.Net;
using System.Security.Claims;

namespace YubicoAuthProvider
{
    public class YubikeyOTP : IAuthenticationAdapter
    {
        private string upn { get; set; }
        private List<string> registeredTokenIDs { get; set; }

        public IAuthenticationAdapterMetadata Metadata
        {
            get { return new AuthenticationAdapterMetadata(); }
        }
        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData) { }
        public void OnAuthenticationPipelineUnload() { }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext context)
        {
            return new AdapterPresentation();
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            this.upn = identityClaim.Value;
            this.registeredTokenIDs = getRegisteredTokenIDs(this.upn);

            return this.registeredTokenIDs.Count > 0;
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            return new AdapterPresentation(ex.Message, true);
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] outgoingClaims)
        {
            string response = string.Empty;
            outgoingClaims = new Claim[0];

            if (ValidateProofData(proofData, context, out response))
            {
                outgoingClaims = new[]
                {
                    new Claim(
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                        "http://schemas.microsoft.com/ws/2012/12/authmethod/otp"
                    )
                };

                return null;
            }

            return new AdapterPresentation(response, false);
        }

        private bool ValidateProofData(IProofData proofData, IAuthenticationContext context, out string response)
        {
            if (proofData == null ||
                    proofData.Properties == null ||
                        !proofData.Properties.ContainsKey("yubikeyotp"))
            {
                throw new ExternalAuthenticationException("Invalid submission - no proof data provided", context);
            }

            string token = proofData.Properties["yubikeyotp"] as string;
            if (string.IsNullOrEmpty(token) || token.Length < 13)
            {
                response = "Authentication failed: Bad One-Time Password";
                return false;
            }

            string tokenID = token.Substring(0, 12);
            if (!registeredTokenIDs.Contains(tokenID))
            {
                response = string.Format("Authentication failed: Unknown Yubikey ID ({0})", tokenID);
                return false;
            }

            YubicoAnswer yubicoAnswer = new YubicoRequest().Validate(token);
            response = yubicoAnswer.Status.ToString();

            if (!yubicoAnswer.IsValid)
                response = string.Format("Authentication failed: {0}", response);

            return yubicoAnswer.IsValid;
        }

        private static List<string> getRegisteredTokenIDs(string upn)
        {
            string userTokenIDAttributeField = ConfigurationManager.AppSettings["yubikeytokenidattributefield"];

            List<string> registeredTokenIDs = new List<string>();
            string searchSyntax = string.Format("(&(objectClass=user)(objectCategory=person)(userPrincipalName={0}))", upn);

            using (DirectoryEntry entry = new DirectoryEntry())
            using (DirectorySearcher mySearcher = new DirectorySearcher(entry, searchSyntax))
            {
                SearchResult result = mySearcher.FindOne();
                if (null != result)
                {
                    var propertyCollection = result.Properties[userTokenIDAttributeField];
                    if (propertyCollection.Count > 0)
                        foreach (object property in propertyCollection)
                            registeredTokenIDs.Add(property as string);
                }
            }

            return registeredTokenIDs;
        }
    }
}
