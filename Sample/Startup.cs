using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Web.Configuration;

[assembly: OwinStartupAttribute(typeof(WebApplication4.Startup))]
namespace WebApplication4
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });
        }
    }
}
