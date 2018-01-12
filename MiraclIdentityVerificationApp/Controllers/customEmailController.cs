using Miracl;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class customEmailController : Controller
    {
        private static Dictionary<string, Identity> StartedRegistration = new Dictionary<string, Identity>();

        // GET: customEmail
        public async Task<ActionResult> Index()
        {
            var activationParams = HomeController.Client.ParseCustomEmailQueryString(Request.QueryString);
            if (activationParams != null)
            {
                var info = await HomeController.Client.GetIdentityInfoAsync(activationParams);
                if (info != null)
                {
                    var identity = new Identity(info, activationParams, 0);
                    StartedRegistration.Add(info.Id, identity);
                    ViewBag.Info = info;
                }
            }

            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Activate(string id)
        {
            ViewBag.IsIdentityActivated = false;
            if (StartedRegistration.ContainsKey(id))
            {
                var identity = StartedRegistration[id];
                ViewBag.Info = identity.Info;

                // apply a custom logic here for validating the identity before activating it
                if (ViewBag.Info != null)
                {
                    if (await HomeController.Client.ActivateIdentityAsync(identity.ActivationParams) == HttpStatusCode.OK)
                    {
                        ViewBag.IsIdentityActivated = true;
                    }
                }
            }
            return View();
        }
    }
}