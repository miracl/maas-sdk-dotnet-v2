using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Miracl;

namespace MiraclIdentityVerificationApp.Controllers
{
    public class pushController : Controller
    {
        private static List<PushViewModel> data = new List<PushViewModel>();

        public ActionResult Index()
        {
            UpdateDataStatus();
            return View(data);
        }

        [HttpPost]
        [ActionName("Index")]
        public ActionResult IndexPost()
        {
            var newUserJson = new System.IO.StreamReader(Request.InputStream).ReadToEnd();
            var identity = HomeController.Client?.HandleNewIdentityPush(newUserJson);

            if (identity != null && !identity.IsExpired())
            {
                data.Add(new PushViewModel(identity));
                return new HttpStatusCodeResult(HttpStatusCode.OK);
            }

            return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
        }

        public ActionResult GetIdentities()
        {
            UpdateDataStatus();
            return PartialView("_IdentitiesTablePartial", data);
        }

        [HttpPost]
        public async Task<ActionResult> Activate(string mPinIdHash, string activateKey)
        {
            var d = data.FirstOrDefault(id => id.Identity.MPinIdHash == mPinIdHash);
            if (d != null && !d.Identity.IsExpired())
            {
                var respStatusCode = await HomeController.Client.ActivateIdentityAsync(mPinIdHash, activateKey);
                if (respStatusCode != HttpStatusCode.OK)
                {
                    ViewBag.ErrorMsg = string.Format("Cannot activate identity. Server responded with status {0} {1}.", (int)respStatusCode, respStatusCode);
                    return View("Error");
                }

                d.Status = IdentityStatus.Activated;
            }

            return RedirectToAction("Index");
        }

        private void UpdateDataStatus()
        {
            foreach (var d in data)
            {
                if (d.Status == IdentityStatus.Pending && d.Identity.IsExpired())
                {
                    d.Status = IdentityStatus.Expired;
                }
            }
        }
    }

    public class PushViewModel
    {
        public Identity Identity { get; private set; }
        public IdentityStatus Status { get; set; }

        public PushViewModel(Identity id)
        {
            this.Identity = id;
            this.Status = IdentityStatus.Pending;
        }
    }

    public enum IdentityStatus
    {
        Pending,
        Activated,
        Expired
    }
}