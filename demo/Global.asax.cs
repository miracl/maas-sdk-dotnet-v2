using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Miracl;

namespace demo
{
    public class MvcApplication : System.Web.HttpApplication
    {
        public static MiraclClient Client { get; private set; }

        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);

            var options = new MiraclAuthenticationOptions
            {
                ClientId = Environment.GetEnvironmentVariable("MFA_CLIENT_ID"),
                ClientSecret = Environment.GetEnvironmentVariable("MFA_CLIENT_SECRET"),
                AuthenticationType = "Cookies"
            };

            Client = new MiraclClient(options);
        }
    }
}
