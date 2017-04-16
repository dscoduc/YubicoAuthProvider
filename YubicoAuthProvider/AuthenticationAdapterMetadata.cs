using Microsoft.IdentityServer.Web.Authentication.External;
using System.Collections.Generic;
using System.Globalization;

namespace YubicoAuthProvider
{
    class AuthenticationAdapterMetadata : IAuthenticationAdapterMetadata
    {
        private string providerName = "Yubico Authentication Provider";
        
        public string AdminName
        {
            get
            {
                return this.providerName;
            }
        }

        public virtual string[] AuthenticationMethods
        {
            get
            {
                return new string[] { "http://schemas.microsoft.com/ws/2012/12/authmethod/otp" };
            }
        }

        public int[] AvailableLcids
        {
            get
            {
                return new[] { new CultureInfo("en-us").LCID };
            }
        }

        public Dictionary<int, string> FriendlyNames
        {
            get
            {
                Dictionary<int, string> _friendlyNames = new Dictionary<int, string>();
                _friendlyNames.Add(new CultureInfo("en-us").LCID, this.providerName);
                return _friendlyNames;
            }
        }

        public Dictionary<int, string> Descriptions
        {
            get
            {
                Dictionary<int, string> _descriptions = new Dictionary<int, string>();
                _descriptions.Add(new CultureInfo("en-us").LCID, this.providerName);
                return _descriptions;
            }
        }

        public string[] IdentityClaims
        {
            get
            {
                return new[] { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" };
            }
        }

        public bool RequiresIdentity
        {
            get
            {
                return true;
            }
        }
    }
}
