using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Net.Http;

namespace Miracl
{
    /// <summary>
    /// Provide configuration used by <see cref="MiraclClient"/> for authentication.
    /// </summary>
    /// <seealso cref="Microsoft.Owin.Security.AuthenticationOptions" />
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
        /// Gets or sets the MIRACL-assigned client id.
        /// </summary>
        /// <value>
        /// The client identifier.
        /// </value>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the MIRACL-assigned client secret.
        /// </summary>
        /// <value>
        /// The client secret.
        /// </value>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the customer identifier registered in the MIRACL platform.
        /// </summary>
        /// <value>
        /// The customer identifier.
        /// </value>
        public string CustomerId { get; set; }

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
        /// Default value is "/login".
        /// </summary>
        /// <value>
        /// The callback path.
        /// </value>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        /// <value>
        /// The state data format.
        /// </value>
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
