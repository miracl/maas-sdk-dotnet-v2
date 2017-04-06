namespace Miracl
{
    internal static class Constants
    {
        internal const string DefaultAuthenticationType = "MIRACL";
        internal const string CallbackString = "/login";
        internal const string ServerBaseAddress = "https://api.mpin.io";
        internal const string DiscoveryPath = "/.well-known/openid-configuration";
        internal const string State = "state";
        internal const string Code = "code";
        internal const string RefreshToken = "refresh_token";
        internal const string ExpiresAt = "expires_at";
        internal const string AccessToken = "access_token";
        internal const string Scope = "openid profile email";
    }
}
