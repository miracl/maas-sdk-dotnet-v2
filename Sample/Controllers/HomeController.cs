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

namespace WebApplication4.Controllers
{

    public class HomeController : Controller
    {
        internal static MiraclClient Client;

        public async Task<ActionResult> Index()
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

            var url = await Client.GetAuthorizationRequestUrlAsync(Request.Url.ToString());
            ViewBag.AuthorizationUri = url;
            return View();
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


