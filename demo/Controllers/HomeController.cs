using Miracl;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace demo.Controllers
{
    public class HomeController : Controller
    {
        public async Task<ActionResult> Index()
        {
            MvcApplication.Client.ClearUserInfo(false);
            Request.GetOwinContext().Authentication.SignOut();

            ViewBag.AuthUrl = await MvcApplication.Client.GetAuthorizationRequestUrlAsync(Request.Url.ToString());

            return View();
        }
    }
}