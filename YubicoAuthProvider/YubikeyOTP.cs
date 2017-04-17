using InsideIAM.Yubico.Library;
using Microsoft.IdentityServer.Web.Authentication.External;
using System.Configuration;
using System.DirectoryServices;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace YubicoAuthProvider
{
    public class YubikeyOTP : IAuthenticationAdapter
    {
        private string upn { get; set; }
        private string registeredTokenID { get; set; }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, System.Net.HttpListenerRequest request, IAuthenticationContext context)
        {
            this.upn = identityClaim.Value;
            return new AdapterPresentation();
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            this.registeredTokenID = getTokenID(identityClaim.Value);

            if (string.IsNullOrEmpty(this.registeredTokenID))
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public IAuthenticationAdapterMetadata Metadata
        {
            get
            {
                return new AuthenticationAdapterMetadata();
            }
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        { }

        public void OnAuthenticationPipelineUnload()
        { }

        public IAdapterPresentation OnError(System.Net.HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            return new AdapterPresentation(ex.Message, true);
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, System.Net.HttpListenerRequest request, out Claim[] outgoingClaims)
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
            else
            {
                return new AdapterPresentation(response, false);
            }
        }

        private bool ValidateProofData(IProofData proofData, IAuthenticationContext context, out string response)
        {
            if (proofData == null ||
                    proofData.Properties == null ||
                        !proofData.Properties.ContainsKey("yubikeytoken"))
            {
                throw new ExternalAuthenticationException("Invalid submission - no proof data provided", context);
            }

            string token = proofData.Properties["yubikeytoken"] as string;
            if (string.IsNullOrEmpty(token) || token.Length < 13)
            {
                response = "Authentication failed: Bad One-Time Password";
                return false;
            }

            string tokenID = token.Substring(0, 12);
            if (!Regex.IsMatch(this.registeredTokenID, tokenID, RegexOptions.IgnoreCase))
            {
                response = string.Format("Authentication failed: Unknown Yubikey ID ({0})", tokenID);
                return false;
            }

            YubicoAnswer yubicoAnswer = new YubicoRequest().Validate(token);
            if(!yubicoAnswer.IsValid)
            {
                response = string.Format("Authentication failed: {0}", yubicoAnswer.Status.ToString());
                return false;
            }

            return true;
        }

        private string getTokenID(string upn)
        {
            /// Requires the entry "yubikeytokenidattributefield" in the AD FS configuration file located
            /// at C:\Windows\ADFS\Microsoft.IdentityServer.Servicehost.exe.config which specifies the
            /// Active Directory attribute storing the Yubikey Token ID for the user object.    
            ///    ex: Key="yubikeytokenidattributefield" Value="extensionAttribute10"
            string userTokenIDAttributeField = ConfigurationManager.AppSettings["yubikeytokenidattributefield"];

            string searchSyntax = string.Format("(&(objectClass=user)(objectCategory=person)(userPrincipalName={0}))", upn);
            using (DirectoryEntry entry = new DirectoryEntry())
            using (DirectorySearcher mySearcher = new DirectorySearcher(entry, searchSyntax))
            {
                SearchResult result = mySearcher.FindOne();
                var propertyCollection = result.Properties[userTokenIDAttributeField];
                if (propertyCollection.Count > 0)
                {
                    //TODO: Handle multi-value attribute instead of single value attribute
                    return (string)result.Properties[userTokenIDAttributeField][0];
                }
            }

            return null;
        }
    }
}
