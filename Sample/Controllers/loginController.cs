using IdentityModel;
using Newtonsoft.Json.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace SampleWebApp.Controllers
{
    public class loginController : Controller
    {
        public async Task<ActionResult> Index()
        {
            if (Request.QueryString == null || string.IsNullOrEmpty(Request.QueryString["code"]) || string.IsNullOrEmpty(Request.QueryString["state"]))
            {
                return View("Error");
            }

            IdentityModel.Client.TokenResponse response = await HomeController.Client.ValidateAuthorization(Request.QueryString);
            if (response != null)
            {
                var identity = await HomeController.Client.GetIdentity(response);
                Request.GetOwinContext().Authentication.SignIn(identity);
            }

            if (!string.IsNullOrEmpty(response.IdentityToken))
            {
                ViewBag.IdentityTokenParsed = ParseJwt(response.IdentityToken);
            }
            if (!string.IsNullOrEmpty(response.AccessToken))
            {
                ViewBag.AccessTokenParsed = ParseJwt(response.AccessToken);
            }
            
            ViewBag.Client = HomeController.Client;

            return View(response);
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
