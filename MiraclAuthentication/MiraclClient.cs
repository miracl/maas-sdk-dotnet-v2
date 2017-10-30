using IdentityModel;
using IdentityModel.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SystemClaims = System.Security.Claims;

namespace Miracl
{
    /// <summary>
    /// Relying Party client class for connecting to the MIRACL server.
    /// </summary>
    public class MiraclClient
    {
        #region Fields
        internal DiscoveryResponse doc;
        internal UserInfoResponse userInfo;
        internal string callbackUrl;
        internal bool requireHttps = true;
        internal RSACryptoServiceProvider dvsRsaPublicKey;
        private TokenResponse accessTokenResponse;
        private List<Claim> claims;
        private ClaimsPrincipal idTokenClaims;
        #endregion

        #region C'tor
        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        public MiraclClient()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclClient"/> class.
        /// </summary>
        /// <param name="options">The options which describes the authenticating parameters.</param>
        public MiraclClient(MiraclAuthenticationOptions options)
            : this()
        {
            this.Options = options;
        }

        #endregion

        #region Members
        /// <summary>
        /// Specifies the MIRACL client objects for authentication.
        /// </summary>
        /// <value>
        /// The options values.
        /// </value>
        public MiraclAuthenticationOptions Options
        {
            get;
            private set;
        }

        /// <summary>
        /// Opaque value set by the RP to maintain state between request and callback.
        /// </summary>
        /// </value>
        /// The State value.
        /// </value>
        public string State
        {
            get;
            internal set;
        }

        /// <summary>
        /// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        /// </summary>
        /// <value>
        /// The Nonce value.
        /// </value>
        public string Nonce
        {
            get;
            internal set;
        }

        /// <summary>
        /// Gets the user identifier name when authenticated.
        /// </summary>
        /// <value>
        /// The user identifier name.
        /// </value>
        public string UserId
        {
            get
            {
                return TryGetValue("sub");
            }
        }

        /// <summary>
        /// Gets the email of the authentication.
        /// </summary>
        /// <value>
        /// The email.
        /// </value>
        public string Email
        {
            get
            {
                return TryGetValue("email");
            }
        }

        #endregion

        #region Methods
        #region Public
        /// <summary>
        /// Constructs redirect URL for authorization via M-Pin system. After URL
        /// redirects back, pass the query string to ValidateAuthorization method to complete
        /// the authorization with server.
        /// </summary>
        /// <param name="baseUri">The base URI of the calling app.</param>
        /// <param name="options">The options for authentication.</param>
        /// <param name="stateString">(Optional) Specify a new Open ID Connect state.</param>
        /// <exception cref="ArgumentException">
        /// <paramref name="baseUri"/> is not a valid Uri.
        /// </exception>
        /// <returns>The callback url.</returns>
        public async Task<string> GetAuthorizationRequestUrlAsync(string baseUri, MiraclAuthenticationOptions options = null, string stateString = null)
        {
            if (!Uri.IsWellFormedUriString(baseUri, UriKind.RelativeOrAbsolute))
            {
                throw new ArgumentException("The baseUri is not well formed", "baseUri");
            }

            this.Options = options ?? this.Options;
            if (this.Options == null)
            {
                throw new ArgumentNullException("MiraclAuthenticationOptions should be set!");
            }

            await LoadOpenIdConnectConfigurationAsync();
            return GetAuthorizationRequestUrl(baseUri, stateString);
        }

        /// <summary>
        /// Returns response with the access token if validation succeeds or None if query string
        /// doesn't contain code and state.
        /// </summary>
        /// <param name="requestQuery">The query string returned from authorization URL.</param>
        /// <param name="redirectUri">The redirect URI. If not specified, it will be taken from the authorization request.</param>
        /// <returns>
        /// The access token from the authentication response.
        /// </returns>
        /// <exception cref="ArgumentNullException">requestQuery</exception>
        /// <exception cref="InvalidOperationException">No Options for authentication! ValidateAuthorization method should be called first!</exception>
        /// <exception cref="ArgumentException">
        /// requestQuery
        /// or
        /// Invalid state!
        /// </exception>
        public async Task<TokenResponse> ValidateAuthorization(NameValueCollection requestQuery, string redirectUri = "")
        {
            if (requestQuery == null)
            {
                throw new ArgumentNullException("requestQuery");
            }

            if (Options == null)
            {
                throw new InvalidOperationException("No Options for authentication! ValidateAuthorization method should be called first!");
            }

            string code = requestQuery[Constants.Code];
            string returnedState = requestQuery[Constants.State];
            string error = requestQuery[Constants.Error];

            if (!string.IsNullOrEmpty(error))
            {
                throw new Exception(error);
            }

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(returnedState))
            {
                throw new ArgumentException(
                    string.Format("requestQuery does not have the proper \"{0}\" and \"{1}\" parameteres.", Constants.Code, Constants.State), "requestQuery");
            }

            if (!State.Equals(returnedState, StringComparison.Ordinal))
            {
                throw new ArgumentException("Invalid state!");
            }

            return await ValidateAuthorizationCode(code, string.Empty, redirectUri);
        }

        /// <summary>
        /// Returns response with the access token if validation of the specified code value succeeds and the user identifier, if passed, corresponds to the identity token one.
        /// </summary>
        /// <param name="code">The code.</param>
        /// <param name="userId">The user identifier. If not specified, the user id verification is not made. </param>
        /// <param name="redirectUri">The redirect URI. If not specified, it will be taken from the authorization request.</param>
        /// <returns>
        /// The access token from the authentication response.
        /// </returns>
        /// <exception cref="System.ArgumentException">Empty redirect uri!</exception>
        public async Task<TokenResponse> ValidateAuthorizationCode(string code, string userId, string redirectUri = "")
        {
            if (string.IsNullOrEmpty(redirectUri) && string.IsNullOrEmpty(callbackUrl))
            {
                throw new ArgumentException("Empty redirect uri!");
            }

            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = callbackUrl;
            }

            var client = this.Options.BackchannelHttpHandler != null
                          ? new TokenClient(doc.TokenEndpoint, this.Options.ClientId, this.Options.ClientSecret, this.Options.BackchannelHttpHandler)
                          : new TokenClient(doc.TokenEndpoint, this.Options.ClientId, this.Options.ClientSecret);

            client.Timeout = this.Options.BackchannelTimeout;
            client.AuthenticationStyle = AuthenticationStyle.PostValues;
            this.accessTokenResponse = await client.RequestAuthorizationCodeAsync(code, redirectUri);
            return IsIdentityTokenValid(userId) ? this.accessTokenResponse : null;
        }

        /// <summary>
        /// Clears the user authorization information.
        /// </summary>
        /// <param name="includingAuth">if set to <c>true</c> the user authentication data is also cleaned.</param>
        public void ClearUserInfo(bool includingAuth = true)
        {
            if (includingAuth)
            {
                this.State = null;
                this.Nonce = null;
                this.Options = null;
            }

            this.callbackUrl = null;
            this.userInfo = null;
            this.accessTokenResponse = null;
        }

        /// <summary>
        /// Determines whether this instance is authorized.
        /// </summary>
        /// <returns>Returns True if access token for the user is available. </returns>
        public bool IsAuthorized()
        {
            return this.accessTokenResponse != null;
        }

        /// <summary>
        /// Gets the identity given by the authentication.
        /// </summary>
        /// <param name="response">The response from the authentication.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">ValidateAuthorization method should be called first!</exception>
        public async Task<ClaimsIdentity> GetIdentity(TokenResponse response)
        {
            if (response == null)
            {
                throw new ArgumentNullException("response");
            }

            if (Options == null)
            {
                throw new InvalidOperationException("No Options for authentication! ValidateAuthorization method should be called first!");
            }

            await FillClaimsAsync(response);
            return new ClaimsIdentity(this.claims,
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
        }

        /// <summary>
        /// Sends signature for verification to the DVS (designated verifier scheme) service and verifies the received response.
        /// </summary>
        /// <param name="signature">The signature to be verified.</param>
        /// <param name="ts">Timestamp showing when the signature was made.</param>
        /// <returns><para cref="VerificationResult"/> object which indicates if the specified signature is properly signed.</para></returns>
        /// <exception cref="ArgumentNullException">Signature cannot be null or empty</exception> 
        /// <exception cref="InvalidOperationException">No Options for verification - client credentials are used for the verification</exception>
        /// <exception cref="ArgumentException">
        /// Timestamp cannot has a negative value
        /// or
        /// DVS public key not found
        /// or
        /// No `certificate` in the JSON response
        /// or
        /// Invalid DVS token format
        /// or
        /// No `hash` in the JWT payload
        /// or
        /// No `hash` in the signature
        /// or
        /// Signature hash and response hash do not match
        /// or
        /// No `cAt` in the signature
        /// or
        /// The transaction is signed before the issue time
        /// </exception>
        public async Task<VerificationResult> DVSVerifySignature(Signature signature, int ts)
        {
            ValidateInput(signature, ts);

            var p = new Payload
            {
                Signature = signature,
                Timestamp = ts,
                Type = "verification"
            };

            var resp = await RequestSignature(p);
            string respContent;
            switch (resp.StatusCode)
            {
                case System.Net.HttpStatusCode.OK:
                    respContent = await resp.Content.ReadAsStringAsync();
                    break;
                case System.Net.HttpStatusCode.Unauthorized:
                    return new VerificationResult() { Status = VerificationStatus.BadPin, IsSignatureValid = false };
                case System.Net.HttpStatusCode.Gone:
                    return new VerificationResult() { Status = VerificationStatus.UserBlocked, IsSignatureValid = false };
                default:
                    return new VerificationResult() { Status = VerificationStatus.MissingSignature, IsSignatureValid = false };
            }

            bool isValid = VerifyResponseSignature(p, respContent);
            var status = isValid ? VerificationStatus.ValidSignature : VerificationStatus.InvalidSignature;
            return new VerificationResult() { Status = status, IsSignatureValid = isValid };
        }

        /// <summary>
        /// Creates a document hash using the SHA256 hashing algorithm.
        /// </summary>
        /// <param name="document">A generic document.</param>
        /// <returns>Hash value of the document as a hex-encoded string</returns>
        public string CreateDocumentHash(string document)
        {
            using (var algorithm = SHA256.Create())
            {
                var hashedBytes = algorithm.ComputeHash(Encoding.UTF8.GetBytes(document));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }

        #endregion

        #region Private
        /// <summary>
        /// Constructs redirect URL for authorization via M-Pin system to be redirected to.
        /// </summary>
        /// <param name="baseUri">The base URI.</param>
        /// <param name="options">The options.</param>
        /// <param name="stateString">The state string.</param>
        /// <returns>Uri for authorization to be redirected to.</returns>
        /// <exception cref="System.ArgumentException">MiraclAuthenticationOptions should be set!</exception>
        private string GetAuthorizationRequestUrl(string baseUri, string stateString = null)
        {
            this.State = stateString ?? Guid.NewGuid().ToString("N");
            this.Nonce = CryptoRandom.CreateUniqueId();

            this.callbackUrl = baseUri.TrimEnd('/') + this.Options.CallbackPath;

            var authRequest = new AuthorizeRequest(doc.AuthorizeEndpoint);
            return authRequest.CreateAuthorizeUrl(clientId: this.Options.ClientId,
                                                    responseType: Constants.Code,
                                                    scope: Constants.Scope,
                                                    redirectUri: callbackUrl,
                                                    state: this.State,
                                                    nonce: this.Nonce);
        }

        private bool IsIdentityTokenValid(string userId)
        {
            bool isUserIdValid = true;
            if (!string.IsNullOrEmpty(userId) && this.accessTokenResponse.IdentityToken != null)
            {
                isUserIdValid = userId == GetUserId(this.accessTokenResponse.IdentityToken);
            }

            if (this.accessTokenResponse == null || string.IsNullOrEmpty(this.accessTokenResponse.IdentityToken))
            {
                throw new ArgumentException("Invalid token data!");
            }

            if (!IsNonceValid(this.accessTokenResponse.IdentityToken))
            {
                throw new ArgumentException("Invalid nonce!");
            }

            this.idTokenClaims = ValidateIdentityToken(this.accessTokenResponse.IdentityToken);
            return isUserIdValid;
        }

        private ClaimsPrincipal ValidateIdentityToken(string idToken)
        {
            string kid = GetKey(idToken);

            SecurityToken securityToken;
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var jwt = jwtSecurityTokenHandler.ReadToken(idToken) as JwtSecurityToken;
            var rsaPublicKey = CreatePublicKey(kid);

            var prms = new TokenValidationParameters()
            {
                IssuerSigningToken = new RsaSecurityToken(rsaPublicKey, kid),
                IssuerSigningKeyResolver = (token, securityToken2, keyIdentifier, validationParameters) =>
                                           { return new RsaSecurityKey(rsaPublicKey); },
                ValidIssuer = doc.TryGetString(OidcConstants.Discovery.Issuer),
                ValidAudience = this.Options.ClientId
            };

            if (UnitTestDetector.IsInUnitTest)
            {
                prms.ValidateLifetime = false;
            }

            return jwtSecurityTokenHandler.ValidateToken(idToken, prms, out securityToken);
        }

        private static string GetKey(string jwt)
        {
            string[] parts = jwt.Split('.');
            if (parts.Length != 3)
            {
                // signed JWT should have header, payload and signature part, separated with a dot
                throw new ArgumentException("Invalid token format");
            }

            string header = parts[0];
            var part = Encoding.UTF8.GetString(Base64Url.Decode(header));
            var headerData = JObject.Parse(part);
            return headerData["kid"].ToString();
        }

        private RSACryptoServiceProvider CreatePublicKey(string kid)
        {
            var cryptoProvider = new RSACryptoServiceProvider();
            foreach (var key in doc.KeySet.Keys)
            {
                if (key.Kty == "RSA" && key.Kid.Equals(kid))
                {
                    cryptoProvider.ImportParameters(new RSAParameters()
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes(key.E),
                        Modulus = Base64UrlEncoder.DecodeBytes(key.N)
                    });
                }
            }

            return cryptoProvider;
        }

        private bool IsNonceValid(string identityToken)
        {
            var idToken = ParseJwt(identityToken);
            var nonce = idToken.GetValue("nonce");
            if (nonce == null || string.IsNullOrEmpty(nonce.ToString()))
            {
                return false;
            }

            return nonce.ToString().Equals(this.Nonce);
        }

        private string GetUserId(string identityToken)
        {
            if (string.IsNullOrEmpty(identityToken))
            {
                return string.Empty;
            }

            var idToken = ParseJwt(identityToken);
            var id = idToken.GetValue("sub");
            return id == null ? string.Empty : id.ToString();
        }

        private JObject ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                throw new ArgumentException("Wrong token data!");
            }

            var parts = token.Split('.');
            var part = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));
            return JObject.Parse(part);
        }

        private async Task LoadOpenIdConnectConfigurationAsync()
        {
            if (doc == null)
            {
                var discoveryClient = GetDiscoveryClient(Constants.DiscoveryPath);
                doc = await discoveryClient.GetAsync();
            }

            if (dvsRsaPublicKey == null)
            {
                var dvsClient = GetDiscoveryClient(Constants.DvsPublicKeyString);
                var pkDoc = await dvsClient.GetAsync();
                await ReadPublicKey(pkDoc);
            }
        }

        private async Task ReadPublicKey(DiscoveryResponse pkDoc)
        {
            var httpClient = this.Options.BackchannelHttpHandler != null ? new HttpClient(this.Options.BackchannelHttpHandler) : new HttpClient();
            var resp = await httpClient.GetAsync(GetBaseAddress() + Constants.DvsPublicKeyString);
            if (resp.StatusCode != System.Net.HttpStatusCode.OK || resp.Content == null)
            {
                throw new ArgumentException("Cannot read public key from " + GetBaseAddress() + Constants.DvsPublicKeyString);
            }
            var content = await resp.Content.ReadAsStringAsync();
            pkDoc.KeySet = new IdentityModel.Jwk.JsonWebKeySet(content);
            if (pkDoc.KeySet.Keys.Count == 1)
            {
                dvsRsaPublicKey = new RSACryptoServiceProvider();
                var key = pkDoc.KeySet.Keys[0];
                if (key.Kty == "RSA" && !string.IsNullOrEmpty(key.N) && !string.IsNullOrEmpty(key.E))
                {
                    dvsRsaPublicKey.ImportParameters(new RSAParameters()
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes(key.E),
                        Modulus = Base64UrlEncoder.DecodeBytes(key.N)
                    });
                }
            }
        }

        private string GetBaseAddress()
        {
            return string.IsNullOrEmpty(this.Options.PlatformAPIAddress) ? Constants.ServerBaseAddress : this.Options.PlatformAPIAddress;
        }

        private DiscoveryClient GetDiscoveryClient(string urlPost)
        {
            var discoveryClient = this.Options.BackchannelHttpHandler != null
                ? new DiscoveryClient(GetBaseAddress() + urlPost, this.Options.BackchannelHttpHandler)
                : new DiscoveryClient(GetBaseAddress() + urlPost);
            if (this.requireHttps == false)
            {
                discoveryClient.Policy = new DiscoveryPolicy { RequireHttps = false };
            }

            return discoveryClient;
        }
        
        private async Task<HttpResponseMessage> RequestSignature(Payload p)
        {
            var httpClient = this.Options.BackchannelHttpHandler != null
                ? new HttpClient(this.Options.BackchannelHttpHandler)
                : new HttpClient();
            
            var payloadString = JsonConvert.SerializeObject(p);
            var content = new StringContent(payloadString, Encoding.UTF8, "application/json");
            httpClient.SetBasicAuthentication(this.Options.ClientId, this.Options.ClientSecret);
            httpClient.DefaultRequestHeaders.Add("Accept", "text/plain");
            return await httpClient.PostAsync(GetBaseAddress() + Constants.DvsVerifyString, content);
        }

        private bool VerifyResponseSignature(Payload p, string respContent)
        {
            var respToken = JObject.Parse(respContent).TryGetString("certificate");
            if (respToken == null)
            {
                throw new ArgumentException("No `certificate` in the JSON response");
            }

            var parts = respToken.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Invalid DVS token format");
            }

            byte[] jwtSignature = Base64Url.Decode(parts[2]);

            var jwtPayload = ParseJwt(respToken);
            var hash = jwtPayload.TryGetString("hash");
            if (hash == null)
            {
                throw new ArgumentException("No `hash` in the JWT payload");
            }

            var docHash = p.Signature.Hash;
            if (!docHash.Equals(hash))
            {
                throw new ArgumentException("Signature hash and response hash do not match");
            }

            var cAt = jwtPayload.TryGetInt("cAt");
            if (cAt == null)
            {
                throw new ArgumentException("No `cAt` in the signature");
            }

            if (p.Timestamp > cAt)
            {
                throw new ArgumentException("The transaction is signed before the issue time");
            }

            return this.dvsRsaPublicKey.VerifyData(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]), "SHA256", jwtSignature);
        }

        private void ValidateInput(Signature signature, int ts)
        {
            if (signature == null)
            {
                throw new ArgumentNullException("Signature cannot be null");
            }

            if (ts < 0)
            {
                throw new ArgumentException("Timestamp cannot has a negative value");
            }

            if (this.Options == null)
            {
                throw new InvalidOperationException("No Options for verification - client credentials are used for the verification");
            }

            if (this.dvsRsaPublicKey == null)
            {
                throw new ArgumentException("DVS public key not found");
            }
        }

        private async Task<IEnumerable<Claim>> GetUserInfoClaimsAsync(string accessToken)
        {
            var userInfoClient = this.Options.BackchannelHttpHandler != null
                ? new UserInfoClient(doc.UserInfoEndpoint, this.Options.BackchannelHttpHandler)
                : new UserInfoClient(doc.UserInfoEndpoint);

            this.userInfo = await userInfoClient.GetAsync(accessToken);
            return this.userInfo.Claims;
        }

        internal async Task FillClaimsAsync(TokenResponse response)
        {
            if (response == null || string.IsNullOrWhiteSpace(response.IdentityToken) || string.IsNullOrEmpty(response.AccessToken))
            {
                throw new ArgumentNullException("The response, its IdentityToken or AccessToken are null!");
            }

            this.claims = new List<SystemClaims.Claim>();
            this.claims.Clear();

            this.claims.AddRange(await GetUserInfoClaimsAsync(response.AccessToken));
            this.claims.Add(new Claim(Constants.AccessToken, response.AccessToken));
            this.claims.Add(new Claim(Constants.ExpiresAt, (DateTime.UtcNow.ToEpochTime() + response.ExpiresIn).ToDateTimeFromEpoch().ToString()));

            if (!string.IsNullOrWhiteSpace(response.RefreshToken))
            {
                this.claims.Add(new Claim(Constants.RefreshToken, response.RefreshToken));
            }
        }

        internal string TryGetValue(string propertyName)
        {
            if (this.userInfo == null || this.userInfo.Json == null)
                return string.Empty;

            JToken value;
            return this.userInfo.Json.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        #endregion
        #endregion
    }
}
