using Microsoft.IdentityServer.Web.Authentication.External;
using System;

namespace YubicoAuthProvider
{
    class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        private string errorMessage { get; set; }
        private bool isPermanentFailure { get; set; }

        public AdapterPresentation()
        {
            this.errorMessage = string.Empty;
            this.isPermanentFailure = false;
        }

        public AdapterPresentation(string message, bool isPermanentFailure)
        {
            this.errorMessage = message;
            this.isPermanentFailure = isPermanentFailure;
        }

        public string GetPageTitle(int lcid)
        {
            return "Yubico Authentication";
        }

        public string GetFormHtml(int lcid)
        {
            string htmlTemplate = string.Empty;
            string errorMessageTemplate = "<div class=\"fieldMargin error smallText\"><label id=\"errorText\">{0}</label></div>";

            if (!String.IsNullOrEmpty(this.errorMessage))
            {
                htmlTemplate += string.Format(errorMessageTemplate, errorMessage);
            }

            if (!this.isPermanentFailure)
            {
                htmlTemplate += Resource.htmlTemplate;
            }

            return htmlTemplate;
        }

        public string GetFormPreRenderHtml(int lcid)
        {
            return string.Empty;
        }
    }
}
