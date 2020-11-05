using IdentityModel.Client;
using Miracl;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Threading.Tasks;
using System.Web;

namespace WebFormApp1
{
    /// <summary>
    /// Summary description for VerifySignatureHandler
    /// </summary>
    public class VerifySignatureHandler : HttpTaskAsyncHandler
    {
        public override async Task ProcessRequestAsync(HttpContext context)
        {
            string verificationData = context.Request["verificationData"];
            string documentData = context.Request["documentData"];
            if (String.IsNullOrEmpty(verificationData) || String.IsNullOrEmpty(documentData))
            {
                context.Response.End();
            }

            var docData = JObject.Parse(documentData);
            var ts = docData.TryGetInt("timestamp");

            var data = JObject.Parse(verificationData);
            var mPinId = data.TryGetString("mpinId");
            var publicKey = data.TryGetString("publicKey");
            var u = data.TryGetString("u");
            var v = data.TryGetString("v");
            var docHash = data.TryGetString("hash");
            JToken dtasValue;
            var dtas = data.TryGetValue("dtas", out dtasValue) ? dtasValue.ToString() : null;

            var signature = new Signature(docHash, mPinId, u, v, publicKey, dtas);
            var timeStamp = ts.HasValue ? ts.Value : 0;
            var verificationResult = await _Default.Client.DvsVerifySignatureAsync(signature, timeStamp);
            
            string json = JsonConvert.SerializeObject(new { verified = verificationResult.IsSignatureValid, status = verificationResult.Status.ToString() });
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.Write(json);
        }
    }
}