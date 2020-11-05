using Newtonsoft.Json;
using System;
using System.Web;

namespace WebFormApp1
{
    /// <summary>
    /// Summary description for CreateDocumentHashHandler
    /// </summary>
    public class CreateDocumentHashHandler : IHttpHandler
    {
        public void ProcessRequest(HttpContext context)
        {
            string document = context.Request["document"];
            if (String.IsNullOrEmpty(document))
            {
                context.Response.End();
            }

            var docHash = _Default.Client.DvsCreateDocumentHash(document);
            var timeStamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            // the mfa.js uses the authToken to verify the validity of the provided PIN
            var authToken = _Default.Client.DvsCreateAuthToken(docHash);
            var documentData = new { hash = docHash, timestamp = timeStamp, authToken };

            string json = JsonConvert.SerializeObject(documentData);
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.Write(json);
        }

        public bool IsReusable
        {
            get
            {
                return false;
            }
        }
    }
}