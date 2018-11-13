using IdentityModel;
using IdentityModel.Client;
using Miracl;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MiraclDvsSigningApp.Controllers
{
    public class loginController : Controller
    {
        public async Task<ActionResult> Index()
        {
            if (Request.QueryString == null || string.IsNullOrEmpty(Request.QueryString["code"]) || string.IsNullOrEmpty(Request.QueryString["state"]))
            {
                return View("Error");
            }

            IdentityModel.Client.TokenResponse response = await HomeController.Client.ValidateAuthorizationAsync(Request.QueryString);
            if (response != null)
            {
                var identity = await HomeController.Client.GetIdentityAsync(response);
                Request.GetOwinContext().Authentication.SignIn(identity);
            }

            if (!string.IsNullOrEmpty(response.AccessToken))
            {
                ViewBag.AccessTokenParsed = ParseJwt(response.AccessToken);
            }

            ViewBag.Client = HomeController.Client;
            ViewBag.RedirectUri = Request.Url.Scheme + "://" + Request.Url.Authority + HomeController.Client.Options.CallbackPath;
            return View(response);
        }

        [HttpPost]
        public JsonResult CreateDocumentHash(string document)
        {
            var docHash = HomeController.Client.DvsCreateDocumentHash(document);
            var timeStamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            // the mfa.js uses the authToken to verify the validity of the provided PIN
            var authToken = HomeController.Client.DvsCreateAuthToken(docHash);
            var documentData = new { hash = docHash, timestamp = timeStamp, authToken };

            return Json(documentData);
        }

        [HttpPost]
        public async Task<JsonResult> VerifySignature(string verificationData)
        {
            var data = JObject.Parse(verificationData);

            var mPinId = data.TryGetString("mpinId");
            var publicKey = data.TryGetString("publicKey");
            var u = data.TryGetString("u");
            var v = data.TryGetString("v");
            var docHash = data.TryGetString("hash");
            var ts = data.TryGetInt("timestamp");
            JToken dtasValue;
            var dtas = data.TryGetValue("dtas", out dtasValue) ? dtasValue.ToString() : null;

            var signature = new Signature(docHash, mPinId, u, v, publicKey, dtas);
            var timeStamp = ts.HasValue ? ts.Value : 0;
            var verificationResult = await HomeController.Client.DvsVerifySignatureAsync(signature, timeStamp);

            return Json(new { verified = verificationResult.IsSignatureValid, status = verificationResult.Status.ToString() });
        }

        private string ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                return token;
            }

            var parts = token.Split('.');
            var part = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));

            var jwt = JObject.Parse(part);
            return jwt.ToString();
        }
    }
}