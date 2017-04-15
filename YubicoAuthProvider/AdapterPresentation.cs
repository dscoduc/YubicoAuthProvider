using Microsoft.IdentityServer.Web.Authentication.External;
using System;

namespace YubicoAuthProvider
{
    class AdapterPresentation : IAdapterPresentation, IAdapterPresentationForm
    {
        private string message = String.Empty;
        private bool isPermanentFailure;
        public string GetPageTitle(int lcid)
        {
            return "Yubico Authentication";
        }

        public string GetFormHtml(int lcid)
        {
            string html = "";
            if (!String.IsNullOrEmpty(this.message))
            {
                html += "<p>" + message + "</p>";
            }

            if (!this.isPermanentFailure)
            {
                html += "<form method=\"post\" id=\"loginForm\" autocomplete=\"off\">";
                html += "<input id=\"authMethod\" type=\"hidden\" name=\"AuthMethod\" value=\"%AuthMethod%\"/>";
                html += "<input id=\"context\" type=\"hidden\" name=\"Context\" value=\"%Context%\"/>";
                html += "<div class=\"groupMargin\"> Insert the YubiKey into a USB port and tap the button. </div>";
                html += "<div class=\"fieldMargin error smallText\"><label id=\"errorText\" for=\"\"></label></div>";
                html += "<div><input id=\"pin\" class=\"text fullWidth\" name=\"pin\" value=\"\" placeholder=\"YubiKey\" tabindex=\"1\" autocomplete=\"off\" autofocus=\"\" /></div>";
                html += "<div class=\"submitMargin\"><input id=\"continueButton\" type=\"submit\" name=\"Continue\" value=\"Continue\" tabindex=\"2\" /></div>";
                html += "</form>";
            }
            return html;
        }

        public string GetFormPreRenderHtml(int lcid)
        {
            return string.Empty;
        }
        public AdapterPresentation()
        {
            this.message = string.Empty;
            this.isPermanentFailure = false;
        }
        public AdapterPresentation(string message, bool isPermanentFailure)
        {
            this.message = message;
            this.isPermanentFailure = isPermanentFailure;
        }
    }
}
