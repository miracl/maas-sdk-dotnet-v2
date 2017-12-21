﻿using Miracl;
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
        // GET: customEmail
        public async Task<ActionResult> Index()
        {
            if (Request.QueryString == null || string.IsNullOrEmpty(Request.QueryString["i"]) || string.IsNullOrEmpty(Request.QueryString["s"]))
            {
                return View();
            }

            var activateKey = Request.QueryString["s"];
            var hashMPinId = Request.QueryString["i"];

            ViewBag.Info = await HomeController.Client.GetIdentityInfoAsync(hashMPinId, activateKey);

            TempData["info"] = ViewBag.Info;
            TempData["hashMPinId"] = hashMPinId;
            TempData["activateKey"] = activateKey;

            return View();
        }

        public async Task<ActionResult> Activate()
        {
            ViewBag.IsIdentityActivated = false;

            var hashMPinId = TempData["hashMPinId"].ToString();
            var activateKey = TempData["activateKey"].ToString();
            ViewBag.Info = TempData["info"];

            // apply a custom logic here for validating the identity before activating it
            if (ViewBag.Info != null)
            {
                if (await HomeController.Client.ActivateIdentityAsync(hashMPinId, activateKey) == HttpStatusCode.OK)
                {
                    ViewBag.IsIdentityActivated = true;
                }
            }

            return View();
        }
    }
}