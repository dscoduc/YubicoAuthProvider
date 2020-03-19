using Microsoft.IdentityServer.Web.Authentication.External;
using NLog;
using System;
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

        // keys for data to be stored in Context
        private const string USERUPN = "userUPN";
        private const string REGISTEREDTOKENIDS = "tokenIDs";

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
            log.Debug("[{0}] New Yubikey authentication request for {1}", context.ActivityId, identityClaim.Value);

            // add userPrincipalName into context data
            context.Data.Add(USERUPN, identityClaim.Value);

            // get registered token IDs for userPrincipalName
            string[] registeredTokenIDs = getRegisteredTokenIDs(identityClaim.Value);

            if (null != registeredTokenIDs && registeredTokenIDs.Length > 0)
            {
                log.Debug("[{0}] Registered Token IDs avialable for {1} - {2}", context.ActivityId, identityClaim.Value, string.Join(",", registeredTokenIDs));
                context.Data.Add(REGISTEREDTOKENIDS, string.Join(",", registeredTokenIDs));
                return true;
            }
            else
            {
                log.Debug("[{0}] No registered Token IDs found in AD for {1}", context.ActivityId, identityClaim.Value);
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

            // retrieve context data stored earlier
            string userPrincipalName = (string)context.Data[USERUPN];

            log.Debug("[{0}] Authentication beginning for {1}", context.ActivityId, userPrincipalName);
            bool isValidated = ValidateProofDataAsync(proofData, context, out responseMessage);

            if (!isValidated)
            {
                log.Info("Authentication failed for {0} - {1}", userPrincipalName, responseMessage);
                authResponse = new AdapterPresentation(responseMessage, false);
            }
            else
            {
                log.Info("Authentication successful for {0}", userPrincipalName);

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
            string userPrincipalName = (string)context.Data[USERUPN];
            string registeredTokenIDs = (string)context.Data[REGISTEREDTOKENIDS];

            if (proofData == null ||
                    proofData.Properties == null ||
                        !proofData.Properties.ContainsKey("yubikeyotp"))
            {
                throw new ExternalAuthenticationException("Invalid submission - no proof data provided", context);
            }

            string otp = proofData.Properties["yubikeyotp"] as string;
            log.Debug("[{0}] Extracted otp {1} from proof data", context.ActivityId, otp ?? "(null)");

            if (string.IsNullOrEmpty(otp) || otp.Length < 13)
            {
                response = "Invalid One-Time Password received";
                return false;
            }

            // extract the first 12 characters of the token id and convert to all lowercase
            string tokenID = otp.Substring(0, 12).ToLower();

            if (Array.IndexOf(registeredTokenIDs.Split(','), tokenID) == -1)
            {
                response = string.Format("Token ID ({0}) not associated with {1}", tokenID, userPrincipalName);
                return false;
            }

            var client = new YubicoClient(yubico_api_client_id, yubico_api_secret_key);
            var yubicoAnswer = client.VerifyAsync(otp).GetAwaiter().GetResult();

            if (yubicoAnswer == null || yubicoAnswer.Status != YubicoResponseStatus.Ok)
            {
                response = yubicoAnswer.Status.ToString();
                return false;
            }

            response = "Authenticated completed successfully";
            return true;
        }

        private static string[] getRegisteredTokenIDs(string upn)
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

            return registeredTokenIDs.ToArray();
        }
    }
}
