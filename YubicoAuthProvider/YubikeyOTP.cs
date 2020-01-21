using Microsoft.IdentityServer.Web.Authentication.External;
using System.Collections.Generic;
using System.Configuration;
using System.DirectoryServices;
using System.Net;
using System.Security.Claims;
using YubicoDotNetClient;

namespace YubicoAuthProvider
{
    public class YubikeyOTP : IAuthenticationAdapter
    {
        private string upn { get; set; }
        private List<string> registeredTokenIDs { get; set; }

        private static string active_directory_token_id_attribute
        {
            get
            {
                return ConfigurationManager.AppSettings.Get("active_directory_token_id_attribute") ?? 
                    throw new System.NullReferenceException("No Active Directory Token Id Attribute found in App.config");
            }
        }

        private string yubico_api_client_id
        {
            get
            {
                return ConfigurationManager.AppSettings.Get("yubico_api_client_id") ?? 
                    throw new System.NullReferenceException("No Yubico Client ID found in App.config");
            }
        }

        private string yubico_api_secret_key
        { 
            get
            {
                return ConfigurationManager.AppSettings.Get("yubico_api_secret_key") ?? 
                    throw new System.NullReferenceException("No Yubico API Secrey Key found in App.config");
            }
        }

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

            if (ValidateProofDataAsync(proofData, context, out response))
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

        private bool ValidateProofDataAsync(IProofData proofData, IAuthenticationContext context, out string response)
        {
            if (proofData == null ||
                    proofData.Properties == null ||
                        !proofData.Properties.ContainsKey("yubikeyotp"))
            {
                throw new ExternalAuthenticationException("Invalid submission - no proof data provided", context);
            }

            string otp = proofData.Properties["yubikeyotp"] as string;
            if (string.IsNullOrEmpty(otp) || otp.Length < 13)
            {
                response = "Authentication failed: Bad One-Time Password";
                return false;
            }

            string tokenID = otp.Substring(0, 12);
            if (!registeredTokenIDs.Contains(tokenID))
            {
                response = string.Format("Authentication failed: Unknown YubiKey ID ({0})", tokenID);
                return false;
            }

            var client = new YubicoClient(yubico_api_client_id, yubico_api_secret_key);
            var yubicoAnswer = client.VerifyAsync(otp).GetAwaiter().GetResult();

            if (yubicoAnswer == null || yubicoAnswer.Status != YubicoResponseStatus.Ok)
            {
                response = string.Format("Authentication failed: {0}", yubicoAnswer.Status.ToString());
                return false;
            }
            else
            {
                response = "Authenticated completed successfully";
                return true;
            }            
        }

        private static List<string> getRegisteredTokenIDs(string upn)
        {
            List<string> registeredTokenIDs = new List<string>();
            string searchSyntax = string.Format("(&(objectClass=user)(objectCategory=person)(userPrincipalName={0}))", upn);

            using (DirectoryEntry entry = new DirectoryEntry())
            using (DirectorySearcher mySearcher = new DirectorySearcher(entry, searchSyntax))
            {
                SearchResult result = mySearcher.FindOne();
                if (null != result)
                {
                    var propertyCollection = result.Properties[active_directory_token_id_attribute];
                    if (propertyCollection.Count > 0)
                        foreach (object property in propertyCollection)
                            registeredTokenIDs.Add(property as string);
                }
            }

            return registeredTokenIDs;
        }
    }
}
