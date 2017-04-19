using IdentityModel;
using IdentityModel.Client;
using Microsoft.Owin.Security.DataHandler;
using Miracl;
using NUnit.Framework;
using RichardSzalay.MockHttp;
using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclClientTests
    {
        private const string Endpoint = "http://nothing";
        private const string TokenEndpoint = "http://nothing/token";
        private const string UserEndpoint = "http://nothing/user";
        private const string AuthorizeEndpoint = "http://nothing/authorize";
        private const string ValidIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAxLTA4LTIwMTYifQ.eyJhbXIiOlsidG9rZW4iXSwiYXVkIjoia2phbzBoOHhiczVzaiIsImV4cCI6MTQ5MTQ3MjI4NywiaWF0IjoxNDkxNDcxMzg3LCJpc3MiOiJodHRwczovL2FwaS5zdGcubWlyYWNsLm5ldCIsIm5vbmNlIjoiZTJkNzQ0ODA0NDVmOWI0YmExNWY5ZTBhYjY2NjlmYzAiLCJzdWIiOiJwZXR5YS5rb2xldmFAbWlyYWNsLmNvbSJ9.KRcC6NvEMll6Nusn-cN3Z56k7bN18mE4utvU3cN6ngKrDpQBw2-PEnP4I5ssyUlKRFcnI77RJOaY_L57Zzze4xyRTacufOuYCGAnnaau-_1D_TcITQAySNShM2D8iOvI9tx_5kX77I9j3YLe5ROwG7B7cFcp0CWnpWB9FaiA7yguQYsSTK8dAi8LqXucwBwiecVO956MXQbBQpV8pekoZ3rqm1Ky9NZ0HrgX1WFu3BhKVxoldVXaZWTKwYBXsvYDMDUi_SOJ555OsG9VkyxXVBaPCZXn45RRy1UjRm2kYQlnCJVBTF84qXQtpps0Or6T_a-nEhHpobo8MerRFYQTVw";
        private const string Nonce = "e2d74480445f9b4ba15f9e0ab6669fc0";

        [Test]
        public void Test_AuthorizationRequestUrl()
        {
            MiraclClient client = new MiraclClient(new MiraclAuthenticationOptions());


            client = new MiraclClient(new MiraclAuthenticationOptions());
            IsClientClear(client, false);
            if (client.doc == null)
            {
                SetDiscovery(client);
            }

            var url = GetRequestUrl(client, Endpoint).Result;

            Assert.That(url, Is.Not.Null);
            Assert.That(client, Has.Property("State").Not.Null);
            Assert.That(client, Has.Property("Nonce").Not.Null);
        }

        private void SetDiscovery(MiraclClient client)
        {
            var discoFileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "documents", "discovery.json");
            var document = File.ReadAllText(discoFileName);

            var _successHandler = new MockHttpMessageHandler();
            _successHandler.When("*").Respond("application/json", document);
            var discoveryClient = new DiscoveryClient(Endpoint, _successHandler);
            discoveryClient.Policy = new DiscoveryPolicy { RequireHttps = false };
            client.doc = discoveryClient.GetAsync().Result;

            Assert.That(client.doc.TryGetValue(OidcConstants.Discovery.AuthorizationEndpoint), Is.Not.Null);
            Assert.That(client.doc.TryGetValue("unknown"), Is.Null);
            Assert.AreEqual(client.doc.TryGetString(OidcConstants.Discovery.AuthorizationEndpoint), AuthorizeEndpoint);
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
            if (client.doc == null)
            {
                SetDiscovery(client);
            }

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

        private static async Task<string> GetRequestUrl(MiraclClient client, string baseUri)
        {
            return await client.GetAuthorizationRequestUrlAsync(baseUri, new MiraclAuthenticationOptions { ClientId = "ClientID" });
        }

        [Test]
        public void Test_Authorization()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
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

            // as it's mock, we don't have discovery and have to set the tokenendpoints manually
            if (client.doc == null)
            {
                SetDiscovery(client);
            }

            var response = client.ValidateAuthorization(nvc, "http://nothing/login").Result;
            Assert.That(response, Is.Not.Null);
            Assert.That(response, Has.Property("AccessToken").EqualTo("MockToken"));
            Assert.That(response, Has.Property("ExpiresIn").EqualTo(600));
            Assert.That(response, Has.Property("IdentityToken").EqualTo(ValidIdToken));
            Assert.That(response, Has.Property("RefreshToken").EqualTo("MockRefresh"));
            Assert.That(response, Has.Property("TokenType").EqualTo("Bearer"));

            var identity = client.GetIdentity(response).Result;
            Assert.That(identity, Is.Not.Null);
            Assert.That(identity, Has.Property("IsAuthenticated").True);
            Assert.That(identity, Has.Property("AuthenticationType").EqualTo("MIRACL"));
            Assert.That(identity, Has.Property("Claims").Not.Null);
            Assert.That(((Claim)(identity.Claims.First())).Type, Is.EqualTo("sub"));
            Assert.That(((Claim)(identity.Claims.First())).Value, Is.EqualTo("noone@miracl.com"));
        }

        private static void IsClientClear(MiraclClient client, bool isAuthorized)
        {
            Assert.That(client, Has.Property("State").Null);
            Assert.That(client, Has.Property("Nonce").Null);
            Assert.That(client, Has.Property("UserId").Null.Or.Property("UserId").Empty);
            Assert.That(client, Has.Property("Email").Null.Or.Property("Email").Empty);
            Assert.That(client.IsAuthorized(), Is.EqualTo(isAuthorized));
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
            NameValueCollection nameValueCollection;
            nameValueCollection = new NameValueCollection();
            nameValueCollection[Constants.State] = "state";

            Assert.That(() => new MiraclClient(new MiraclAuthenticationOptions()).ValidateAuthorization(nameValueCollection),
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
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\""+ValidIdToken+"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            mockHttp.When(UserEndpoint).Respond("application/json", "{\"sub\":\"noone@miracl.com\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.BackchannelHttpHandler = mockHttp;
            options.ClientId = "MockClient";
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
        public void Test_ValidateAuthorizationCode()
        {
            var mockHttp = new MockHttpMessageHandler();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"" + ValidIdToken + "\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");

            MiraclAuthenticationOptions options = new MiraclAuthenticationOptions();
            options.ClientId = "MockClient";
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
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid nonce!"));
            
            mockHttp.Clear();
            mockHttp.When(TokenEndpoint).Respond("application/json", "{\"access_token\":\"MockToken\",\"expires_in\":600,\"id_token\":\"\",\"refresh_token\":\"MockRefresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}");
            Assert.That(() => client.ValidateAuthorizationCode("MockCode", "empty@id.token"),
                Throws.TypeOf<ArgumentException>().And.Message.EqualTo("Invalid nonce!"));
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
        }
    }
}
