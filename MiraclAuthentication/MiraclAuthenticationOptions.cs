using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Miracl
{
    public class MiraclAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Initializes a new <see cref="MiraclAuthenticationOptions"/>
        /// </summary>
        public MiraclAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            CallbackPath = new PathString(Constants.CallbackString);
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        /// <summary>
        /// Gets or sets the MIRACL-assigned client id
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the MIRACL-assigned client secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with the MIRACL server.
        /// </summary>
        /// <value>
        /// The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The HTTP handler stack to use for sending requests.
        /// </summary>
        /// <value>
        /// The HTTP handler stack.
        /// </value>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-miracl".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the platform API address.
        /// If not set, the default is used. 
        /// For advanced usage only!
        /// </summary>
        /// <value>
        /// The platform API address.
        /// </value>
        public string PlatformAPIAddress { get; set; }
    }
}
