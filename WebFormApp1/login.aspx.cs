using System;
using System.Text;
using System.Web;
using IdentityModel;
using Newtonsoft.Json.Linq;

namespace WebFormApp1
{
    public partial class login : System.Web.UI.Page
    {
        protected async void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                string query = ((System.Web.UI.Page)sender).ClientQueryString;
                if (Request.QueryString == null || string.IsNullOrEmpty(Request.QueryString["code"]) || string.IsNullOrEmpty(Request.QueryString["state"]))
                {
                    return; // "Error"
                }

                IdentityModel.Client.TokenResponse response = await _Default.Client.ValidateAuthorizationAsync(Request.QueryString);
                if (response != null)
                {
                    var identity = await _Default.Client.GetIdentityAsync(response);
                    Request.GetOwinContext().Authentication.SignIn(identity);
                }

                userId.Text = _Default.Client.UserId;
                platformApi.Value = _Default.Client.Options.PlatformAPIAddress;
                clientID.Value = _Default.Client.Options.ClientId;
                redirectURI.Value = Request.Url.Scheme + "://" + Request.Url.Authority + _Default.Client.Options.CallbackPath;

                if (!string.IsNullOrEmpty(response.AccessToken))
                {
                    accessTokenTB.Text = ParseJwt(response.AccessToken);
                }
            }
        }

        protected void LogoutBtn_Click(object sender, EventArgs e)
        {
            var authenticationManager = HttpContext.Current.GetOwinContext().Authentication;
            authenticationManager.SignOut();
            Response.Redirect("~/Default.aspx", false);
        }

        private string ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                return token;
            }

            var parts = token.Split('.');
            var part = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));

            var jwt = JObject.Parse(part);
            return jwt.ToString();
        }
    }
}