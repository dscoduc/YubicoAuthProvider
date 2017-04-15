using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace YubicoAuthProvider
{
    class YubikeyOTP
    {
    }

    public class AuthenticationAdapter : IAuthenticationAdapter
    {
        public IAuthenticationAdapterMetadata Metadata
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext context)
        {
            throw new NotImplementedException();
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext context)
        {
            throw new NotImplementedException();
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            throw new NotImplementedException();
        }

        public void OnAuthenticationPipelineUnload()
        {
            throw new NotImplementedException();
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            throw new NotImplementedException();
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext context, IProofData proofData, HttpListenerRequest request, out Claim[] claims)
        {
            throw new NotImplementedException();
        }
    }
}
