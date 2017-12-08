using Microsoft.Owin;
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

namespace MiraclIdentityVerificationApp.Controllers
{
    public enum UserVerificationMethod
    {
        StandardEmail,
        CustomEmail,
        FullCustomPull,
        FullCustomPush
    }

    public class HomeController : Controller
    {
        private static MiraclClient StandardEmailClient;
        private static MiraclClient CustomEmailClient;
        private static MiraclClient FullCustomPushClient;
        private static MiraclClient FullCustomPullClient;
        internal static MiraclClient Client;

        #region Actions
        public async Task<ActionResult> Index()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.StandardEmail);
            ViewBag.VerificationFlow = UserVerificationMethod.StandardEmail.ToString();
            return View();
        }

        [HttpPost]
        public ActionResult Index(string data)
        {
            Logout();
            return RedirectToAction("Index");
        }

        public async Task<ActionResult> CustomEmail()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.CustomEmail);
            ViewBag.VerificationFlow = UserVerificationMethod.CustomEmail.ToString();
            return View("Index");
        }

        [HttpPost]
        public ActionResult CustomEmail(string data)
        {
            Logout();
            return RedirectToAction("CustomEmail");
        }

        public async Task<ActionResult> FullCustomPush()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.FullCustomPush);
            ViewBag.VerificationFlow = UserVerificationMethod.FullCustomPush.ToString();
            return View("Index");
        }

        [HttpPost]
        public ActionResult FullCustomPush(string data)
        {
            Logout();
            return RedirectToAction("FullCustomPush");
        }

        public async Task<ActionResult> FullCustomPull()
        {
            ViewBag.AuthorizationUri = await GetUrl(GetAbsoluteRequestUrl(), UserVerificationMethod.FullCustomPull);
            ViewBag.VerificationFlow = UserVerificationMethod.FullCustomPull.ToString();
            return View("Index");
        }

        [HttpPost]
        public ActionResult FullCustomPull(string data)
        {
            Logout();
            return RedirectToAction("FullCustomPull");
        }

        #endregion

        #region Methods
        private static async Task<string> GetUrl(string url, UserVerificationMethod method)
        {
            return await GetClient(method).GetAuthorizationRequestUrlAsync(url);
        }

        private string GetAbsoluteRequestUrl()
        {
            return Request.Url.Segments.Count() > 1 
                    ? Request.Url.AbsoluteUri.Replace(Request.Url.AbsolutePath, "")
                    : Request.Url.AbsoluteUri;
        }

        private static MiraclClient GetClient(UserVerificationMethod method)
        {
            switch (method)
            {
                case UserVerificationMethod.StandardEmail:
                    if (StandardEmailClient == null)
                    {
                        StandardEmailClient = new MiraclClient(new MiraclAuthenticationOptions
                        {
                            ClientId = ConfigurationManager.AppSettings["StandardEmailClientId"],
                            ClientSecret = ConfigurationManager.AppSettings["StandardEmailClientSecret"],
                            AuthenticationType = "Cookies"
                        });
                    }
                    Client = StandardEmailClient;
                    break;
                case UserVerificationMethod.CustomEmail:
                    if (CustomEmailClient == null)
                    {
                        CustomEmailClient = new MiraclClient(new MiraclAuthenticationOptions
                        {
                            ClientId = ConfigurationManager.AppSettings["CustomEmailClientId"],
                            ClientSecret = ConfigurationManager.AppSettings["CustomEmailClientSecret"],
                            AuthenticationType = "Cookies"
                        });
                    }
                    Client = CustomEmailClient;
                    break;  
                case UserVerificationMethod.FullCustomPush:
                    if (FullCustomPushClient == null)
                    {
                        // Note that in this flow we need a CustomerId too as the identity registration token is signed with it
                        FullCustomPushClient = new MiraclClient(new MiraclAuthenticationOptions
                        {
                            ClientId = ConfigurationManager.AppSettings["FullCustomPushClientId"],
                            ClientSecret = ConfigurationManager.AppSettings["FullCustomPushClientSecret"],
                            CustomerId = ConfigurationManager.AppSettings["FullCustomPushCustomerId"],
                            AuthenticationType = "Cookies"
                        });
                    }
                    Client = FullCustomPushClient;
                    break;
                case UserVerificationMethod.FullCustomPull:
                    if (FullCustomPullClient == null)
                    {
                        FullCustomPullClient = new MiraclClient(new MiraclAuthenticationOptions
                        {
                            ClientId = ConfigurationManager.AppSettings["FullCustomPullClientId"],
                            ClientSecret = ConfigurationManager.AppSettings["FullCustomPullClientSecret"],
                            AuthenticationType = "Cookies"
                        });
                    }
                    Client = FullCustomPullClient;
                    break;
            }

            return Client;
        }

        private void Logout()
        {
            if (Request.Form["Logout"] == "Logout")
            {
                StandardEmailClient?.ClearUserInfo(false);
                CustomEmailClient?.ClearUserInfo(false);
                FullCustomPushClient?.ClearUserInfo(false);
                FullCustomPullClient?.ClearUserInfo(false);
                Request.GetOwinContext().Authentication.SignOut();
            }
        }        
        #endregion
    }
}


