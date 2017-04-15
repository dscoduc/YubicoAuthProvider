using InsideIAM.Yubico.Library;
using Microsoft.IdentityServer.Web.Authentication.External;
using System.Configuration;
using System.DirectoryServices;
using System.Security.Claims;

/// <summary>
/// Copy .DLL files into C:\Windows\ADFS
///     - YubicoAuthProvider.dll
///     - Yubico.Library.dll
/// 
/// Add app.config sections to C:\Windows\ADFS\Microsoft.IdentityServer.Servicehost.exe.config
/// 
/// Update config with YubikeyCloud ID and Key
/// 
/// Register into AD FS using the following command:
/// 
///     $typeName = "YubicoAuthProvider.YubikeyOTP, YubicoAuthProvider, Version=1.0.0.0, Culture=neutral, PublicKeyToken=7649c32bf1339c5d"; 
///     Register-AdfsAuthenticationProvider -TypeName $typeName -Name "YubicoAuthProvider" -Verbose
/// 
/// Restart AD FS services
/// 
/// </summary>
namespace YubicoAuthProvider
{
    public class YubikeyOTP : IAuthenticationAdapter
    {
        private string userTokenIDAttributeField = ConfigurationManager.AppSettings["yubikeytokenidattributefield"];
        private string upn;
        private string registeredTokenID;

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, System.Net.HttpListenerRequest request, IAuthenticationContext context)
        {
            this.upn = identityClaim.Value;
            return new AdapterPresentation();
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            this.registeredTokenID = getTokenID(identityClaim.Value);
            return !string.IsNullOrEmpty(this.registeredTokenID);
        }

        public IAuthenticationAdapterMetadata Metadata
        {
            get { return new AuthenticationAdapterMetadata(); }
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {

        }

        public void OnAuthenticationPipelineUnload()
        {

        }

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
                    new Claim( "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                    "http://schemas.microsoft.com/ws/2012/12/authmethod/otp" )
                };

                return null;
            }
            else
            {
                return new AdapterPresentation(response, false);
            }
        }

        private bool ValidateProofData(IProofData proofData, IAuthenticationContext context, out string yubicoResponse)
        {
            if (proofData == null || proofData.Properties == null || !proofData.Properties.ContainsKey("pin"))
                throw new ExternalAuthenticationException("Invalid Yubikey token", context);

            string otp = proofData.Properties["pin"] as string;
            string tokenID = otp.Substring(0, 12);

            //string registeredTokenID = getTokenID(upn);
            if (string.IsNullOrEmpty(otp) || 
                    string.IsNullOrEmpty(this.registeredTokenID) || 
                        this.registeredTokenID.ToLower() != tokenID.ToLower())
            {
                yubicoResponse = "Invalid or unregistered Token ID provided";
                return false;
            }

            YubicoAnswer yubicoAnswer = new YubicoRequest().Validate(otp);
            yubicoResponse = yubicoAnswer.Status.ToString();

            return yubicoAnswer.IsValid;
        }

        private string getTokenID(string upn)
        {
            string searchSyntax = string.Format("(&(objectClass=user)(objectCategory=person)(userPrincipalName={0}))", upn);
            using (DirectoryEntry entry = new DirectoryEntry())
            using (DirectorySearcher mySearcher = new DirectorySearcher(entry, searchSyntax))
            {
                SearchResult result = mySearcher.FindOne();
                var propertyCollection = result.Properties[this.userTokenIDAttributeField];
                if (propertyCollection.Count > 0)
                {
                    return (string)result.Properties[this.userTokenIDAttributeField][0];
                }
                
                return null;
            }
        }
    }
}
