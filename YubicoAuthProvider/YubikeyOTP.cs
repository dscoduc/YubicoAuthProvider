using Microsoft.IdentityServer.Web.Authentication.External;
using NLog;
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
        private static Logger log = LogManager.GetCurrentClassLogger();
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

            log.Debug("Checking if Yubikey authentication is available for {0}", this.upn);

            this.registeredTokenIDs = getRegisteredTokenIDs(this.upn);

            if (this.registeredTokenIDs.Count > 0)
            {
                log.Debug("Available - registered Token IDs : {0}", string.Join(",", this.registeredTokenIDs));
                return true;
            }
            else
            {
                log.Debug("Unavailable - no registered Token IDs found in Active Directory.");
                return false;
            }
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            log.Error(ex);
            return new AdapterPresentation(ex.Message, true);
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] outgoingClaims)
        {
            AdapterPresentation authResponse = null;
            string responseMessage = null;
            outgoingClaims = new Claim[0];

            log.Debug("Authentication beginning for {0}", this.upn);

            bool isValidated = ValidateProofDataAsync(proofData, context, out responseMessage);

            log.Debug(responseMessage);

            if (!isValidated)
            {
                authResponse = new AdapterPresentation(responseMessage, false);
            }
            else
            {
                outgoingClaims = new[]
                {
                    new Claim(
                        "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                        "http://schemas.microsoft.com/ws/2012/12/authmethod/otp"
                    )
                };
            }

            return authResponse;
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
            log.Debug("Extracted otp {0} from proof data", otp ?? "(null)");

            if (string.IsNullOrEmpty(otp) || otp.Length < 13)
            {
                response = "Authentication failed: Invalid One-Time Password received";
                return false;
            }

            string tokenID = otp.Substring(0, 12);
            if (!registeredTokenIDs.Contains(tokenID))
            {
                response = string.Format("Authentication failed: Token ID ({0}) not associated with {1}", tokenID, upn);
                return false;
            }

            var client = new YubicoClient(yubico_api_client_id, yubico_api_secret_key);
            var yubicoAnswer = client.VerifyAsync(otp).GetAwaiter().GetResult();

            if (yubicoAnswer == null || yubicoAnswer.Status != YubicoResponseStatus.Ok)
            {
                response = string.Format("Authentication failed: {0}", yubicoAnswer.Status.ToString());
                return false;
            }

            response = "Authenticated completed successfully";
            return true;
        }

        private static List<string> getRegisteredTokenIDs(string upn)
        {
            List<string> registeredTokenIDs = new List<string>();
            string searchSyntax = string.Format("(&(objectClass=user)(objectCategory=person)(userPrincipalName={0}))", upn);

            SearchResult searchResult = null;
            try
            {
                using (DirectoryEntry entry = new DirectoryEntry())
                using (DirectorySearcher mySearcher = new DirectorySearcher(entry, searchSyntax))
                {
                    searchResult = mySearcher.FindOne();
                    if (null != searchResult)
                    {
                        var propertyCollection = searchResult.Properties[active_directory_token_id_attribute];
                        if (propertyCollection.Count > 0)
                            foreach (object property in propertyCollection)
                                registeredTokenIDs.Add(property as string);
                    }
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                searchResult = null;
            }

            return registeredTokenIDs;
        }
    }
}
