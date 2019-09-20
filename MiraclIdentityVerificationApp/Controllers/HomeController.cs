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
        FullCustomRPInitiated
    }

    public class HomeController : Controller
    {
        private static MiraclClient StandardEmailClient;
        private static MiraclClient FullCustomRPInitiatedClient;
        private static UserVerificationMethod ClientMethod;
        internal static MiraclClient Client;

        #region Actions
        public ActionResult Index()
        {
            SetupUserVerificationMethod(UserVerificationMethod.StandardEmail);
            return View();
        }

        [HttpPost]
        public ActionResult Index(string data)
        {
            Logout();
            return RedirectToAction("Index");
        }

        public ActionResult FullCustomRPInitiated()
        {
            SetupUserVerificationMethod(UserVerificationMethod.FullCustomRPInitiated);
            return View("Index");
        }

        [HttpPost]
        public ActionResult FullCustomRPInitiated(string data)
        {
            Logout();
            return RedirectToAction("FullCustomPull");
        }

        public async Task<ActionResult> Login(string identity)
        {
            if (ClientMethod == UserVerificationMethod.FullCustomRPInitiated)
            {
                if (string.IsNullOrEmpty(identity))
                {
                    ViewBag.ErrorMsg = "You need to enter an email which you want to start the custom RP initiated authentication with.";
                    return View("Error");
                }
                // here the app could validate the identity and then proceed with its activation and registration
                string device = System.Net.Dns.GetHostName();
                string authUri = await GetClient(UserVerificationMethod.FullCustomRPInitiated).GetRPInitiatedAuthUriAsync(identity, device, GetAbsoluteRequestUrl());
                return Redirect(authUri);
            }

            var authorizationUri = await GetUrl(GetAbsoluteRequestUrl(), ClientMethod, identity);
            return Redirect(authorizationUri);
        }

        public async Task<ActionResult> Logout(string data)
        {
            Logout();
            return View("Index");
        }

        #endregion

        #region Methods

        private void SetupUserVerificationMethod(UserVerificationMethod method)
        {
            ClientMethod = method;
            ViewBag.VerificationFlow = method.ToString();
        }

        private static async Task<string> GetUrl(string url, UserVerificationMethod method, string identity = null)
        {
            var authorizationUri = await GetClient(method).GetAuthorizationRequestUrlAsync(url);
            // The following code is used to populate prerollid if provided during the authentication process
            if (!string.IsNullOrEmpty(identity))
            {
                authorizationUri += "&prerollid=" + identity;
            }
            return authorizationUri;
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
                case UserVerificationMethod.FullCustomRPInitiated:
                    if (FullCustomRPInitiatedClient == null)
                    {
                        FullCustomRPInitiatedClient = new MiraclClient(new MiraclAuthenticationOptions
                        {
                            ClientId = ConfigurationManager.AppSettings["FullCustomRPInitiatedClientId"],
                            ClientSecret = ConfigurationManager.AppSettings["FullCustomRPInitiatedClientSecret"],
                            AuthenticationType = "Cookies"
                        });
                    }
                    Client = FullCustomRPInitiatedClient;
                    break;
            }

            return Client;
        }

        private void Logout()
        {
            StandardEmailClient?.ClearUserInfo(false);
            FullCustomRPInitiatedClient?.ClearUserInfo(false);
            Request.GetOwinContext().Authentication.SignOut();
        }
        #endregion
    }
}


