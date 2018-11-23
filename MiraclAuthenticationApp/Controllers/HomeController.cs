using Miracl;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.UI;

namespace SampleWebApp.Controllers
{
    public class HomeController : Controller
    {
        internal static MiraclClient Client;

        public ActionResult Index()
        {
            return View();
        }

        public async Task<ActionResult> Login(string email)
        {
            var url = Request.Url.Scheme + "://" + Request.Url.Authority;
            var authorizationUri = await GetUrl(url);
            // The following code is used to populate prerollid if provided during the authentication process
            if (!string.IsNullOrEmpty(email))
            {
                authorizationUri += "&prerollid=" + email;
            }
            return Redirect(authorizationUri);
        }

        public ActionResult Logout()
        {
            Client?.ClearUserInfo(false);
            Request.GetOwinContext().Authentication.SignOut();
            return RedirectToAction("Index");
        }

        internal static async Task<string> GetUrl(string url)
        {
            if (Client == null)
            {
                Client = new MiraclClient(new MiraclAuthenticationOptions
                {
                    ClientId = ConfigurationManager.AppSettings["ClientId"],
                    ClientSecret = ConfigurationManager.AppSettings["ClientSecret"],
                    AuthenticationType = "Cookies"
                });
            }

            return await Client.GetAuthorizationRequestUrlAsync(url);
        }

    }
}


