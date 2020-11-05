using Miracl;
using System;
using System.Web;
using System.Web.UI;

namespace WebFormApp1
{
    public partial class _Default : Page
    {
        private static MiraclClient client; 
        public static MiraclClient Client {
            get
            {
                if (client == null)
                {
                    client = new MiraclClient(new MiraclAuthenticationOptions
                    {
                        ClientId = "CLIENT ID",
                        ClientSecret = "CLIENT SECRET",
                        CustomerId = "CUSTOMER ID",
                        PlatformAPIAddress = "https://api.mpin.io"
                    });
                }

                return client;
            }
        }

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                if (User.Identity.IsAuthenticated)
                {
                    LogoutBtn.Visible = true;
                }
                else
                {
                    LoginForm.Visible = true;
                }
            }
        }

        protected async void LoginBtn_Click(object sender, EventArgs e)
        {
            var url = Request.Url.Scheme + "://" + Request.Url.Authority;
            var authorizationUri = await Client.GetAuthorizationRequestUrlAsync(url);

            // The following code is used to populate prerollid if provided during the authentication process
            if (!string.IsNullOrEmpty(this.PrerollID.Text))
            {
                authorizationUri += "&prerollid=" + this.PrerollID.Text;
            }

            Response.Redirect(authorizationUri, false);
        }
        
        protected void LogoutBtn_Click(object sender, EventArgs e)
        {
            var authenticationManager = HttpContext.Current.GetOwinContext().Authentication;
            authenticationManager.SignOut();
        }
    }
}