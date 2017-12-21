using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class pullController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.ActivationStarted = false;
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Index(string id)
        {
            ViewBag.ActivationStarted = false;
            var identity = await HomeController.Client.HandleNewIdentityPullAsync(id);

            if (identity != null && !identity.IsExpired())
            {
                ViewBag.ActivationStarted = true;
                ViewBag.Info = identity.Info;
                TempData["identity"] = identity;
            }
            else
            {
                if(!string.IsNullOrEmpty(id))
                {
                    ViewBag.Id = id;
                }
            }
            
            return View();
        }

        public async Task<ActionResult> Activate()
        {
            ViewBag.IsIdentityActivated = false;
            var identity = TempData["identity"] as Miracl.Identity;

            // check here if the identity is valid and if so, call ActivateIdentityAsync of the current client object
            if (identity != null)
            {
                if (await HomeController.Client.ActivateIdentityAsync(identity.MPinIdHash, identity.ActivateKey) == HttpStatusCode.OK)
                {
                    var resStatusCode = await HomeController.Client.ActivateIdentityAsync(identity.MPinIdHash, identity.ActivateKey);
                    ViewBag.IsIdentityActivated = !identity.IsEmpty() && resStatusCode == HttpStatusCode.OK;
                    ViewBag.Info = identity.Info;
                }
            }

            return View();
        }
    }
}