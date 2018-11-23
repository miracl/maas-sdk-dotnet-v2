using Miracl;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace demo.Controllers
{
    public class dvsController : Controller
    {
        [HttpPost]
        public async Task<JsonResult> VerifySignature()
        {
            string reqBody = new StreamReader(Request.InputStream).ReadToEnd();

            var data = JObject.Parse(reqBody);
            var sign = data.TryGetValue("signature", out JToken value) ? value : null;

            var mPinId = sign.Value<string>("mpinId");
            var publicKey = sign.Value<string>("publicKey");
            var u = sign.Value<string>("u");
            var v = sign.Value<string>("v");
            var docHash = sign.Value<string>("hash");
            var timeStamp = data.Value<int?>("timestamp") ?? 0;
            JToken dtasValue;
            var dtas = data.TryGetValue("dtas", out dtasValue) ? dtasValue.ToString() : null;

            var signature = new Signature(docHash, mPinId, u, v, publicKey, dtas);
            var verificationResult = await MvcApplication.Client.DvsVerifySignatureAsync(signature, timeStamp);

            return Json(new { valid = verificationResult.IsSignatureValid, status = verificationResult.Status.ToString() });
        }

        [HttpPost]
        public JsonResult CreateDocumentHash()
        {
            string document = new StreamReader(Request.InputStream).ReadToEnd();

            var docHash = MvcApplication.Client.DvsCreateDocumentHash(document);
            var timeStamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            var documentData = new { hash = docHash, timestamp = timeStamp };

            return Json(documentData);
        }
    }
}
