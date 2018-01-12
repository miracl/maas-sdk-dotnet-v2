﻿using System;
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
        private static List<PushViewModel> Data = new List<PushViewModel>();

        public ActionResult Index()
        {
            UpdateDataStatus();
            return View(Data);
        }

        [HttpPost]
        [ActionName("Index")]
        public ActionResult IndexPost()
        {
            var newUserJson = new System.IO.StreamReader(Request.InputStream).ReadToEnd();
            var identity = HomeController.Client?.HandleNewIdentityPush(newUserJson);

            if (identity != null && !identity.IsExpired())
            {
                Data.Add(new PushViewModel(identity));
                return new HttpStatusCodeResult(HttpStatusCode.OK);
            }

            return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
        }

        public ActionResult GetIdentities()
        {
            UpdateDataStatus();
            return PartialView("_IdentitiesTablePartial", Data);
        }

        [HttpPost]
        public async Task<ActionResult> Activate(string mPinIdHash)
        {
            var d = Data.FirstOrDefault(id => id.Identity.ActivationParams.MPinIdHash == mPinIdHash);
            if (d != null && d.Identity != null && !d.Identity.IsExpired())
            {
                var respStatusCode = await HomeController.Client.ActivateIdentityAsync(d.Identity.ActivationParams);
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
            foreach (var d in Data)
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