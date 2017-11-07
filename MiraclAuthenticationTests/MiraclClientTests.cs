using IdentityModel;
using IdentityModel.Client;
using Microsoft.Owin.Security.DataHandler;
using Miracl;
using NUnit.Framework;
using RichardSzalay.MockHttp;
using System;
using System.Collections.Specialized;
using System.IdentityModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclClientTests
    {
        #region Consts
        private const string Endpoint = "https://api.dev.miracl.net";
        private const string TokenEndpoint = "https://api.dev.miracl.net/oidc/token";
        private const string UserEndpoint = "https://api.dev.miracl.net/oidc/userinfo";
        private const string AuthorizeEndpoint = "https://api.dev.miracl.net/authorize";
        private const string DVSVerifyEndpoint = "https://api.dev.miracl.net/dvs/verify";
        private const string DVSPubKeysEndpoint = "https://api.dev.miracl.net/dvs/jwks";
        private const string CertUri = "https://api.dev.miracl.net/oidc/certs";
        private const string ValidClientId = "gnuei07bcyee8";
        private const string ValidAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJjaWQiOiJnbnVlaTA3YmN5ZWU4IiwiZXhwIjoxNDkzMDE2NDk5LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiXSwic3ViIjoicGV0eWEua29sZXZhQG1pcmFjbC5jb20ifQ.MKPhkQ6-QbPIuD68cfy6QmuqelFUs1yUmW2dZn3ovjC8BkdCdgzRzysAvdTQCGe8F-WRTIAdmY00rXmC-z4_VVG1yESdOP2eCOD7zFmIXF9m5OTKMJJEaG6SOUoko5jypohmDk4MuLjOvfMOhXQfWKqLxkliMmM2e8J1FjSY7sF6Azg0Pq_mqK-mznIofbzR7tnA22XmlF_GRqYyoRpUEtkzU2ydoU9oGSJrwtwTeN1vXlzEwSvj65mVkuP4dIqJ5fmYstgTyKlzkwe8wFDHhB3Px-89lh5JRYKoY0nbDIUOc0RA0dKFnnFX3P0Cp9kp2QOwXYdRLmdhvhn7IeJjjw";
        private const string ValidIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.CTQu9bx7vCV6pZvtDhEJTFjeasMJoZtbq93vFj2nwVODaGj5Ajp9ZYZvhD7eeYtOBzBH0rOAjNc_348bZXjiqi3IdpEMCTiQz0dPqxTlywUjwM0HCMQ0C0TIwUh4f8Os0rthF1a1yYy_WgL7FgFsmb12xwTwt_TXrKHqbHXV-eX8ip0GCQgao9B1VC3Jj4NEfEXuUSq2nexEx-p_H9LgqbNBro3i_kPoP7C3wfiSFS30qDDUKZLp3SeW90-ErcNQKmU7rukvujeCpeziYlycLyeRTPVmAOTMEyO4ABQyk4KTl_w9P2O8AXW6a2B7nfjGAQGVT_m9Z_56yzgJoJ9KRg";
        private const string Nonce = "80fcd53d3576621da623e1fdbe6c7c51416a975a3e53898ccb0bdeeb084be42f";
        private readonly Signature SignatureToVerify = new Signature("15760473979d2027bebca22d4e0ae40f49d0756dda507de71df99bf04d2a7d07",
                                                                      "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
                                                                       "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
                                                                       "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
                                                                       "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b");
        #endregion // Consts

        #region Tests
        [Test]
        public void Test_AuthorizationRequestUrl()
        {
            MiraclClient client = new MiraclClient(new MiraclAuthenticationOptions());

            client = new MiraclClient(new MiraclAuthenticationOptions());
            IsClientClear(client, false);

            SetDiscovery(client);
            SetRsaPublicKey(client);

            var url = GetRequestUrl(client, Endpoint).Result;

            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("State").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
        }

        [Test]
        public void Test_AuthorizationRequestUrl_NullUri()
        {
            MiraclClient client = new MiraclClient();
            Assert.That(() => GetRequestUrl(client, null),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_AuthorizationRequestUrl_InvalidUri()
        {
            MiraclClient client = new MiraclClient();
            Assert.That(() => GetRequestUrl(client, "Not a URI"),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("baseUri"));
        }

        [Test]
        public void Test_AuthorizationRequestUr_NoOptions()
        {
            MiraclClient client = new MiraclClient();
            client.doc = new DiscoveryResponse("");
            Assert.That(() => client.GetAuthorizationRequestUrlAsync(AuthorizeEndpoint),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("MiraclAuthenticationOptions should be set!"));
        }

        [Test]
        public void Test_ClearUserInfo()
        {
            MiraclClient client = new MiraclClient(new MiraclAuthenticationOptions());
            IsClientClear(client, false);

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually            
            SetDiscovery(client);
            SetRsaPublicKey(client);


            var url = GetRequestUrl(client, "http://nothing").Result;
            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("State").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);

            client.ClearUserInfo(false);
            Assert.That(client, Has.Property("State").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
            Assert.That(client, Has.Property("Options").Not.Null);
            Assert.That(client, Has.Property("UserId").Null.Or.Property("UserId").Empty);
            Assert.That(client, Has.Property("Email").Null.Or.Property("Email").Empty);
            Assert.That(client.IsAuthorized(), Is.False);

            client.ClearUserInfo();
            IsClientClear(client, false);
        }

        [Test]
        public void Test_Authorization()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"" + ValidAccessToken + "\",\"expires_in\":900,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"email\":\"petya.koleva@miracl.com\",\"sub\":\"petya.koleva@miracl.com\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = ValidClientId;
            options.ClientSecret = "q0Hog6cY2pAt3V-0MPXgRfcM9FTNT5gFGr7JvxRXce4";
            options.BackchannelTimeout = TimeSpan.FromMinutes(1);
            options.BackchannelHttpHandler = mockHttp;
            options.PlatformAPIAddress = Endpoint;
            options.CallbackPath = new Microsoft.Owin.PathString("/login");
            options.StateDataFormat = new PropertiesDataFormat(null);

            MiraclClient client = new MiraclClient(options);
            Assert.That(client.Options.PlatformAPIAddress, Is.EqualTo(Endpoint));
            Assert.That(client.Options.StateDataFormat, Is.TypeOf(typeof(PropertiesDataFormat)));

            // Inject the handler or client into your application code
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "59Mu-PxYsj--mOId9etkOw";
            nvc["state"] = "MockState";
            client.State = nvc["state"];
            client.Nonce = Nonce;

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            SetDiscovery(client);

            var response = client.ValidateAuthorization(nvc, "http://nothing/login").Result;
            Assert.That(response, Is.Not.Null);
            Assert.That(response, Has.Property("AccessToken").EqualTo(ValidAccessToken));
            Assert.That(response, Has.Property("ExpiresIn").EqualTo(900));
            Assert.That(response, Has.Property("IdentityToken").EqualTo(ValidIdToken));
            Assert.That(response, Has.Property("RefreshToken").EqualTo("MockRefresh"));
            Assert.That(response, Has.Property("TokenType").EqualTo("Bearer"));

            var identity = client.GetIdentity(response).Result;
            Assert.That(identity, Is.Not.Null);
            Assert.That(identity, Has.Property("IsAuthenticated").True);
            Assert.That(identity, Has.Property("AuthenticationType").EqualTo("MIRACL"));
            Assert.That(identity, Has.Property("Claims").Not.Null);
            Assert.That(((Claim)(identity.Claims.First())).Type, Is.EqualTo("email"));
            Assert.That(((Claim)(identity.Claims.First())).Value, Is.EqualTo("petya.koleva@miracl.com"));
            Assert.IsTrue(identity.Claims.Where((a) => a.Type.Equals("sub") & a.Value.Equals("petya.koleva@miracl.com")).Count() > 0);
        }

        [Test]
        public void Test_ValidateAuthorization_NullRequestQuery()
        {
            Assert.That(() => new MiraclClient().ValidateAuthorization(null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_NoOptions()
        {
            MiraclClient client = new MiraclClient();
            // Inject the handler or client into your application code
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];

            Assert.That(() => new MiraclClient().ValidateAuthorization(nvc, "http://nothing/SigninMiracl"),
                Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void Test_ValidateAuthorization_MissingCode()
        {
            NameValueCollection nvc = new NameValueCollection();
            nvc[Constants.State] = "state";

            Assert.That(() => new MiraclClient(new MiraclAuthenticationOptions()).ValidateAuthorization(nvc),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_MissingState()
        {
            NameValueCollection nameValueCollection;
            nameValueCollection = new NameValueCollection();
            nameValueCollection[Constants.Code] = "code";

            Assert.That(() => new MiraclClient(new MiraclAuthenticationOptions()).ValidateAuthorization(nameValueCollection),
                Throws.TypeOf<ArgumentException>().And.Property("ParamName").EqualTo("requestQuery"));
        }

        [Test]
        public void Test_ValidateAuthorization_InvalidState()
        {
            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            MiraclClient client = new MiraclClient(options);
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = "DifferentState";

            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/SigninMiracl"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid state!"));
        }

        [Test]
        public void Test_ValidateAuthorization_NoRedirectUrl()
        {
            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            MiraclClient client = new MiraclClient(options);
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];

            Assert.That(() => client.ValidateAuthorization(nvc),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Empty redirect uri!"));
        }

        [Test]
        public void Test_ValidateAuthorization_UseCallbackUrl()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.BackchannelHttpHandler = mockHttp;
            options.ClientId = ValidClientId;
            options.ClientSecret = "MockSecret";
            MiraclClient client = new MiraclClient(options);
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];
            client.Nonce = Nonce;
            client.callbackUrl = "/CallbackPath";
            SetDiscovery(client);

            var response = client.ValidateAuthorization(nvc).Result;
            Assert.That(response, Is.Not.Null);
            Assert.That(response.AccessToken, Is.EqualTo("MockToken"));
        }

        [Test]
        public void Test_ValidateAuthorization_Error()
        {
            NameValueCollection nvc = new NameValueCollection();
            nvc[Constants.State] = "state";
            nvc[Constants.Error] = "some error";

            Assert.That(() => new MiraclClient(new MiraclAuthenticationOptions()).ValidateAuthorization(nvc),
                Throws.TypeOf<Exception>().And.Message.EqualTo("some error"));
        }

        [Test]
        public void Test_ValidateAuthorizationCode()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = ValidClientId;
            options.ClientSecret = "MockSecret";
            options.BackchannelHttpHandler = mockHttp;
            MiraclClient client = new MiraclClient(options);
            client.callbackUrl = "/CallbackPath";
            client.Nonce = Nonce;
            SetDiscovery(client);

            var response = client.ValidateAuthorizationCode("MockCode", "wrong@mail.me").Result;
            Assert.That(response, Is.Null);

            response = client.ValidateAuthorizationCode("MockCode", "petya.koleva@miracl.com").Result;
            Assert.That(response, Is.Not.Null);
            Assert.That(response.RefreshToken, Is.EqualTo("MockRefresh"));
            Assert.That(response.AccessToken, Is.EqualTo("MockToken"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "empty@id.token"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid token data!"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "empty@id.token"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid token data!"));
        }

        [Test]
        public void Test_GetIdentity_NullResponse()
        {
            Assert.That(() => new MiraclClient().GetIdentity(null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("response"));
        }

        [Test]
        public void Test_GetIdentity_NoOptions()
        {
            Assert.That(() => new MiraclClient().GetIdentity(new IdentityModel.Client.TokenResponse("{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"MockIdToken\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}")),
               Throws.TypeOf<InvalidOperationException>().And.Message.EqualTo("No Options for authentication! ValidateAuthorization method should be called first!"));
        }

        [Test]
        public void Test_FillClaimsAsync_NoResponse()
        {
            Assert.That(() => new MiraclClient().FillClaimsAsync(null),
                Throws.TypeOf<ArgumentNullException>().And.Message.Contains("The response, its IdentityToken or AccessToken are null!"));
        }

        [Test]
        public void Test_TryGetValue()
        {
            var client = new MiraclClient();
            client.userInfo = new UserInfoResponse("{\"sub\":\"noone@miracl.com\"}");
            Assert.That(client.TryGetValue("sub"), Is.EqualTo("noone@miracl.com"));
        }

        [Test]
        public void Test_LoadOpenIdConnectConfigurationAsync()
        {
            var discoFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery.json");
            var document = File.ReadAllText(discoFileName);
            var _successHandler = new MockHttpMessageHandler();
            _successHandler.When("*").Respond("application/json", document);

            MiraclAuthenticationOptions o = new MiraclAuthenticationOptions()
            {
                PlatformAPIAddress = Endpoint,
                BackchannelHttpHandler = _successHandler
            };
            var client = new MiraclClient(o);
            client.requireHttps = false;

            Assert.That(client.doc, Is.Null);

            var url = client.GetAuthorizationRequestUrlAsync(Endpoint).Result;
            Assert.That(client.doc, Is.Not.Null);
            Assert.That(client.doc.TryGetString(OidcConstants.Discovery.AuthorizationEndpoint), Is.EqualTo(AuthorizeEndpoint));
        }

        [Test]
        public void Test_ParseJwt_InvalidToken()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"InvalidIdToken\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = "MockClient";
            options.ClientSecret = "MockSecret";
            options.BackchannelTimeout = TimeSpan.FromMinutes(1);
            options.BackchannelHttpHandler = mockHttp;
            options.PlatformAPIAddress = Endpoint;
            options.CallbackPath = new Microsoft.Owin.PathString("/CallbackPath");
            options.StateDataFormat = new PropertiesDataFormat(null);

            MiraclClient client = new MiraclClient(options);
            Assert.That(client.Options.PlatformAPIAddress, Is.EqualTo(Endpoint));
            Assert.That(client.Options.StateDataFormat, Is.TypeOf(typeof(PropertiesDataFormat)));

            // Inject the handler or client into your application code
            NameValueCollection nvc = new NameValueCollection();
            nvc["code"] = "MockCode";
            nvc["state"] = "MockState";
            client.State = nvc["state"];
            client.Nonce = Nonce;
            SetDiscovery(client);

            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                 Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Wrong token data!"));

            mockHttp.Clear();
            var noNonce = "33.eyJhbGciOiJSUzI1NiIsImtpZCI6IjAxLTA4LTIwMTYifQ";
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + noNonce + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid nonce!"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0" + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid token format"));

            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMxLTA3LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoiZ251ZWkwN2JjeWVlOCIsImV4cCI6MTQ5MzAxNjc3NSwiaWF0IjoxNDkzMDE1ODc1LCJpc3MiOiJodHRwczovL2FwaS5kZXYubWlyYWNsLm5ldCIsIm5vbmNlIjoiODBmY2Q1M2QzNTc2NjIxZGE2MjNlMWZkYmU2YzdjNTE0MTZhOTc1YTNlNTM4OThjY2IwYmRlZWIwODRiZTQyZiIsInN1YiI6InBldHlhLmtvbGV2YUBtaXJhY2wuY29tIn0.invalidSignature" + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorization(nvc, "http://nothing/login"),
                Throws.TypeOf<SignatureVerificationFailedException>().And.Message.Contains("Signature validation failed"));
        }

        [Test]
        public void Test_GetAuthorizationRequestUrlAsync_DVSPublicKeyResponseNotOK()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(System.Net.Http.HttpMethod.Get, DVSPubKeysEndpoint).Respond(HttpStatusCode.NotFound, "application/json", "pk");

            var client = InitClient("MockClient", "MockSecret", mockHttp);
            SetDiscovery(client);

            Assert.That(() => client.GetAuthorizationRequestUrlAsync(Endpoint),
                               Throws.TypeOf<ArgumentException>().And.Message.Contains("Cannot read public key"));

            mockHttp.Clear();
            mockHttp.When(System.Net.Http.HttpMethod.Get, DVSPubKeysEndpoint).Respond(HttpStatusCode.OK, null);

            Assert.That(() => client.GetAuthorizationRequestUrlAsync(Endpoint),
                               Throws.TypeOf<ArgumentException>().And.Message.Contains("Cannot read public key"));
        }

        [TestCase("", "s", "d", "d", "b")]
        [TestCase(null, "s", "d", "d", "b")]
        [TestCase("2", "", "d", "d", "b")]
        [TestCase("3", null, "d", "d", "b")]
        [TestCase("w", "s", "", "d", "b")]
        [TestCase("w", "s", null, "d", "b")]
        [TestCase("w", "s", "d", "", "b")]
        [TestCase("e", "s", "d", null, "b")]
        [TestCase("s", "s", "d", "d", "")]
        [TestCase("f", "s", "d", "d", null)]
        public void Test_Signature(string hash, string u, string v, string publicKey, string mpinId)
        {
            Signature s;
            Assert.That(() => s = new Signature(hash, mpinId, u, v, publicKey),
               Throws.TypeOf<ArgumentNullException>().And.Message.Contains("Value cannot be null"));            
        }

        [Test]
        public void Test_DVSVerifySignature()
        {
            MiraclClient client = InitClient();
            SetDiscovery(client);
            var url = client.GetAuthorizationRequestUrlAsync(Endpoint).Result;

            var resp = client.DvsVerifySignature(SignatureToVerify, 0).Result;

            Assert.IsTrue(resp.IsSignatureValid);
            Assert.AreEqual(VerificationStatus.ValidSignature, resp.Status);
        }

        [Test]
        public void Test_DVSVerifySignature_InvalidSignature()
        {
            MiraclClient client = InitClient();
            SetRsaPublicKey(client);

            Assert.That(() => client.DvsVerifySignature(null, 0),
               Throws.TypeOf<ArgumentNullException>().And.Message.Contains("Signature cannot be null"));
        }

        [Test]
        public void Test_DVSVerifySignature_InvalidTimestamp()
        {
            var client = new MiraclClient();

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, -1),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Timestamp cannot has a negative value"));
        }

        [Test]
        public void Test_DVSVerifySignature_NullClientOptions()
        {
            var client = new MiraclClient();

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<InvalidOperationException>().And.Message.Contains("No Options for verification - client credentials are used for the verification"));
        }

        [Test]
        public void Test_DVSVerifySignature_NullClientRsaPublicKey()
        {
            var client = InitClient();

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("DVS public key not found"));
        }

        [TestCase(null, null)]
        [TestCase(null, "MockSecret")]
        [TestCase("", "")]
        [TestCase("", "MockSecret")]
        public void Test_DVSVerifySignature_InvalidClientIdAndSecret(string clientId, string clientSecret)
        {
            MiraclClient client = InitClient(clientId, clientSecret);
            SetRsaPublicKey(client);

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<ArgumentNullException>());
        }

        [TestCase(HttpStatusCode.Unauthorized, VerificationStatus.BadPin)]
        [TestCase(HttpStatusCode.Gone, VerificationStatus.UserBlocked)]
        [TestCase(HttpStatusCode.Forbidden, VerificationStatus.MissingSignature)]
        public void Test_DVSVerifySignature_ServerResponseStatusNotOK(HttpStatusCode respStatusCode, VerificationStatus expected)
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DVSVerifyEndpoint).Respond(respStatusCode, "application/json", string.Empty);

            var client = InitClient("MockClient", "MockSecret", mockHttp);
            SetRsaPublicKey(client);

            var resp = client.DvsVerifySignature(SignatureToVerify, 0).Result;

            Assert.IsFalse(resp.IsSignatureValid);
            Assert.AreEqual(expected, resp.Status);
        }

        [Test]
        public void Test_DVSVerifySignature_ServerResponseStatusOK_InvalidResponse()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DVSVerifyEndpoint).Respond("application/json", "{\"no-certificate\":\"ey.fQ.nD\"}");
            var client = InitClient("MockClient", "MockSecret", mockHttp);
            SetRsaPublicKey(client);

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
                Throws.TypeOf<ArgumentException>().And.Message.Contains("No `certificate` in the JSON response"));

            mockHttp.Clear();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DVSVerifyEndpoint).Respond("application/json", "{\"certificate\":\"ey.fQ\"}");
            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Invalid DVS token"));

            mockHttp.Clear();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DVSVerifyEndpoint).Respond("application/json", "{\"certificate\":\"eyfQnD\"}");
            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Invalid DVS token"));

            mockHttp.Clear();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DVSVerifyEndpoint).Respond("application/json", "\"invalid\":\"json\"}");
            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, 0),
               Throws.TypeOf<Newtonsoft.Json.JsonReaderException>());
        }

        [Test]
        public void Test_DVSVerifySignature_ServerResponseStatusOK_RequestAndResponseHashesDiffer()
        {
            MiraclClient client = InitClient();
            SetRsaPublicKey(client);

            Signature signature = new Signature("different-hash-value",
                                                "7b226973737565644174223a313439373335363536352c22757365724944223a2273616d75656c652e616e6472656f6c69406578616d706c652e636f6d222c22634944223a22222c226d6f62696c65223a312c2273616c74223a223236343330323663373430363162363162616465643836313262373530626334222c2276223a317d",
                                                "041c9e2ae817f033140a2085add0594643ca44381dae76e0241cbf790371a7f3c406b31ba86b3cd0d744f0a2e87dbcc32d19416d15aaae91f9122cb4d12cb78f07",
                                                "040ef9b951522009900127820a9a956486b9e11ad05e18e4e86931460d310a2ecf106c9935dc0775a41892577b2f96f87c556dbe87f8fcf7fda546ec21752beada",
                                                "0f9b60020f2a6108c052ba5d2ac0b24b8b7975ae2a2082ddb5d51b236662620e0c05f8310abe5fbda9ed80d638887ed2859f22b9c902bf88bd52dd083ce26e93144e03e61ad2e14722d29e21fde4eaa9f33f793db7da5e3f6211a7d99a8186e023c7fc60de7185a5d73d11b393530d0245256f7ecc0b1c7c96513b1c717a9b1b");

            Assert.That(() => client.DvsVerifySignature(signature, 0),
               Throws.TypeOf<ArgumentException>().And.Message.Contains("Signature hash and response hash do not match"));
        }

        [Test]
        public void Test_DVSVerifySignature_ServerResponseStatusOK_RequestTimestampAfterResponseTimestamp()
        {
            MiraclClient client = InitClient();
            SetRsaPublicKey(client);

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, int.MaxValue),
              Throws.TypeOf<ArgumentException>().And.Message.Contains("The transaction is signed before the issue time"));
        }

        [TestCase("eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MX0", "No `hash` in the JWT payload")]
        [TestCase("eyJleHAiOjE0OTc0NDQ0NjEsImhhc2giOiIxNTc2MDQ3Mzk3OWQyMDI3YmViY2EyMmQ0ZTBhZTQwZjQ5ZDA3NTZkZGE1MDdkZTcxZGY5OWJmMDRkMmE3ZDA3In0", "No `cAt` in the signature")]
        public void Test_DVSVerifySignature_ServerResponseStatusOK_InvalidResponsePayload(string payload, string expected)
        {
            string respContent = string.Format("{{\"certificate\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.{0}.A19LAJpEZjFhwor0bj02AGh9\"}}", payload);

            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(System.Net.Http.HttpMethod.Post, DVSVerifyEndpoint).Respond("application/json", respContent);

            var client = InitClient("MockClient", "MockSecret", mockHttp);
            SetRsaPublicKey(client);

            Assert.That(() => client.DvsVerifySignature(SignatureToVerify, int.MaxValue),
              Throws.TypeOf<ArgumentException>().And.Message.Contains(expected));
        }

        [Test]
        public void Test_DVSVerifySignature_ServerResponseStatusOK_PublicKeyNotMatching()
        {
            var client = InitClient();
            SetRsaPublicKey(client);

            var resp = client.DvsVerifySignature(SignatureToVerify, 0).Result;

            Assert.IsFalse(resp.IsSignatureValid);
            Assert.AreEqual(VerificationStatus.InvalidSignature, resp.Status);
        }

        [Test]
        public void Test_CreateDocumentHash()
        {
            string document = "sample document";
            string expected = "1789c9eeee7dcbf9a5e9b47374e244f85263dc45922a249d37f7ba9fd4efb850";

            Assert.AreEqual(expected, new MiraclClient().DvsCreateDocumentHash(document));
        }
         #endregion // Tests

            #region Methods
            private static async Task<string> GetRequestUrl(MiraclClient client, string baseUri)
        {
            return await client.GetAuthorizationRequestUrlAsync(baseUri, new MiraclAuthenticationOptions { ClientId = "ClientID" });
        }

        private static void IsClientClear(MiraclClient client, bool isAuthorized)
        {
            Assert.That(client, Has.Property("State").Null);
            Assert.That(client, Has.Property("Nonce").Null);
            Assert.That(client, Has.Property("UserId").Null.Or.Property("UserId").Empty);
            Assert.That(client, Has.Property("Email").Null.Or.Property("Email").Empty);
            Assert.That(client.IsAuthorized(), Is.EqualTo(isAuthorized));
        }

        private void SetDiscovery(MiraclClient client)
        {
            var discoFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery.json");
            var document = File.ReadAllText(discoFileName);

            var jwksFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery_jwks.json");
            var jwks = File.ReadAllText(jwksFileName);

            var _successHandler = new MockHttpMessageHandler();
            _successHandler.When(Endpoint + "/.well-known/openid-configuration").Respond("application/json", document);
            _successHandler.When(CertUri).Respond("application/json", jwks);

            var discoveryClient = new DiscoveryClient(Endpoint, _successHandler);
            discoveryClient.Policy = new DiscoveryPolicy { RequireHttps = false };
            client.doc = discoveryClient.GetAsync().Result;

            Assert.That(client.doc.TryGetValue(OidcConstants.Discovery.AuthorizationEndpoint), Is.Not.Null);
            Assert.That(client.doc.TryGetValue("unknown"), Is.Null);
            Assert.AreEqual(client.doc.TryGetString(OidcConstants.Discovery.AuthorizationEndpoint), AuthorizeEndpoint);
            Assert.That(client.doc.KeySet.Keys.Count, Is.EqualTo(1));
            Assert.That(client.doc.KeySet.Keys[0].Kty, Is.EqualTo("RSA"));
        }

        private void SetRsaPublicKey(MiraclClient client)
        {
            client.dvsRsaPublicKey = new System.Security.Cryptography.RSACryptoServiceProvider();
        }

        private MockHttpMessageHandler GetDefaultMockHttp()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(HttpMethod.Post, DVSVerifyEndpoint).Respond("application/json", "{\"certificate\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJjQXQiOjE0OTc0NDQ0NTEsImV4cCI6MTQ5NzQ0NDQ2MSwiaGFzaCI6IjE1NzYwNDczOTc5ZDIwMjdiZWJjYTIyZDRlMGFlNDBmNDlkMDc1NmRkYTUwN2RlNzFkZjk5YmYwNGQyYTdkMDcifQ.A19LAJpEZjFhwor0bj02AGh9Nu_VGtyNXeJhqSe1uWc16kJA3Mi7Oe5ocFRUbb5xRuQ8TkzL9kjjiE3CgHLFftCDswHQqLX6nIH6oamVd0lt3fbgAu3pJBtK9U2BKSxwT7q-pQNFuPJTs-3P8XAwegJAbUouHUKuKL1zJTnDmQk\"}");
            mockHttp.When(HttpMethod.Get, DVSPubKeysEndpoint).Respond("application/json", "{\"keys\": [{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"s1\",\"n\":\"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k\",\"e\":\"AQAB\"}]}");
            return mockHttp;
        }

        private MiraclClient InitClient(string clientId = "MockClient", string clientSecret = "MockSecret", MockHttpMessageHandler mockHttp = null)
        {
            if (mockHttp == null)
            {
                mockHttp = GetDefaultMockHttp();
            }

            var options = new MiraclAuthenticationOptions();
            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.BackchannelHttpHandler = mockHttp;
            options.PlatformAPIAddress = Endpoint;

            var client = new MiraclClient(options);
            return client;
        }
        #endregion // Methods
    }
}
