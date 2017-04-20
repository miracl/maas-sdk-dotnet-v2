using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace WebApplication4.Controllers
{
    public class authtokenController : Controller
    {
        [HttpPost]
        public async Task<ActionResult> Index()
        {
            string data = new System.IO.StreamReader(Request.InputStream).ReadToEnd();
            JToken code, userId;
            try
            {
                var d = JObject.Parse(data);
                if (!d.TryGetValue("code", out code) || !d.TryGetValue("userID", out userId))
                {
                    return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
                }
            }
            catch
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            var token = await HomeController.Client.ValidateAuthorizationCode(code.ToString(), userId.ToString());
            if (token == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.Unauthorized);
            }
            if (!string.IsNullOrEmpty(token.Error))
            {
                return new HttpStatusCodeResult(token.HttpStatusCode == 0 ? HttpStatusCode.BadRequest : token.HttpStatusCode, token.Error);
            }

            return Json(token);
        }
    }
}