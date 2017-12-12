using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class pushController : Controller
    {
        [HttpPost]
        public async Task<ActionResult> Index()
        {
            var newUserJson = new System.IO.StreamReader(Request.InputStream).ReadToEnd();
            var identity = HomeController.Client?.HandleNewIdentityPush(newUserJson);

            // add custom logic to decide if the identity could be activated or not, we check only if the identity is existing and not expired
            if (identity != null && !identity.IsExpired())
            {
                return new HttpStatusCodeResult(await HomeController.Client.ActivateIdentityAsync(identity.MPinIdHash, identity.ActivateKey));
            }

            return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
        }
    }
}