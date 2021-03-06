namespace Miracl
{
    internal static class Constants
    {
        internal const string DefaultAuthenticationType = "MIRACL";
        internal const string CallbackString = "/login";
        internal const string DvsVerifyString = "/dvs/verify";
        internal const string DvsPublicKeyString = "/dvs/jwks";
        internal const string ServerBaseAddress = "https://api.mpin.io";
        internal const string DiscoveryPath = "/.well-known/openid-configuration";
        internal const string State = "state";
        internal const string Code = "code";
        internal const string Error = "error";
        internal const string RefreshToken = "refresh_token";
        internal const string ExpiresAt = "expires_at";
        internal const string AccessToken = "access_token";
        internal const string Scope = "openid profile email dvs mpin_id hash_mpin_id";
        internal const string ActivateEndpoint = "/activate/user";
        internal const string ActivateInitiateEndpoint = "/activate/initiate";
        internal const string UserIdClaim = "sub";
        internal const string EmailClaim = "email";
        internal const string MPinIDClaim = "mpin_id";
        internal const string HashMPinIDClaim = "hash_mpin_id";
    }
}
