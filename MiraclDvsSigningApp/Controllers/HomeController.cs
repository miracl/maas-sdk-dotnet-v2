using Miracl;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MiraclDvsSigningApp.Controllers
{
    public class HomeController : Controller
    {
        internal static MiraclClient Client;

        public async Task<ActionResult> Index()
        {
            ViewBag.AuthorizationUri = await GetUrl(Request.Url.ToString());
            return View();
        }

        internal static async Task<string> GetUrl(string url)
        {
            if (Client == null)
            {
                Client = new MiraclClient(new MiraclAuthenticationOptions
                {
                    ClientId = ConfigurationManager.AppSettings["ClientId"],
                    ClientSecret = ConfigurationManager.AppSettings["ClientSecret"],
                    CustomerId = ConfigurationManager.AppSettings["CustomerId"],
                    PlatformAPIAddress = "https://api.mpin.io",
                    AuthenticationType = "Cookies"
                });
            }

            return await Client.GetAuthorizationRequestUrlAsync(url);
        }

        [HttpPost]
        public ActionResult Index(string Logout)
        {
            if (Logout != null)
            {
                Client.ClearUserInfo(false);
                Request.GetOwinContext().Authentication.SignOut();
            }

            return RedirectToAction("Index");
        }
    }
}