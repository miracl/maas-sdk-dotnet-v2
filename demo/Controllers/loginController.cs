using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Miracl;

namespace demo.Controllers
{
    public class loginController : Controller
    {
        public async Task<ActionResult> Index()
        {
            if (Request.QueryString == null || string.IsNullOrEmpty(Request.QueryString["code"]) || string.IsNullOrEmpty(Request.QueryString["state"]))
            {
                return View("Error");
            }

            TokenResponse response = await MvcApplication.Client.ValidateAuthorizationAsync(Request.QueryString);
            if (response != null)
            {
                var identity = await MvcApplication.Client.GetIdentityAsync(response);
                Request.GetOwinContext().Authentication.SignIn(identity);
            }

            ViewBag.Client = MvcApplication.Client;

            return View();
        }
    }
}