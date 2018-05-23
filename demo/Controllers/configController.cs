using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Miracl;

namespace demo.Controllers
{
    public class configController : Controller
    {
        public async Task<JsonResult> Index()
        {
            MvcApplication.Client.ClearUserInfo(false);

            var url = "http://localhost:8000";
            var authUrl = await MvcApplication.Client.GetAuthorizationRequestUrlAsync(url);
            var redirectURL = url + MvcApplication.Client.Options.CallbackPath;

            Uri l = new Uri(authUrl);
            var query = HttpUtility.ParseQueryString(l.Query);

            string state = query["state"];
            string nonce = query["nonce"];

            var demoCfg = new
            {
                clientID = MvcApplication.Client.Options.ClientId,
                redirectURL,
                state,
                nonce
            };

            return Json(demoCfg, JsonRequestBehavior.AllowGet);
        }
    }
}