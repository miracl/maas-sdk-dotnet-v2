using IdentityModel.Client;
using Miracl;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class DvsIntegrationTests
    {
        #region Fields
        private const string Endpoint = "https://api.mpin.io";
        private string ClientId = Environment.GetEnvironmentVariable("MFA_CLIENT_ID");
        private string ClientSecret = Environment.GetEnvironmentVariable("MFA_CLIENT_SECRET");
        private string ClientRedirectUri = "http://127.0.0.1:2403/login";
        #endregion

        #region Tests
        [Test]
        public void Test_DvsIntegration()
        {
            var document = "test document";
            var signature = GenerateSignature(document);

            var signatureJson = JObject.Parse(signature);
            var s = signatureJson.TryGetString("signature");
            var timestamp = signatureJson.TryGetInt("timestamp");
            var ts = timestamp.HasValue ? timestamp.Value : 0;
            var signatureToVerify = JsonConvert.DeserializeObject(s, typeof(Signature)) as Signature;

            var client = InitIntegrationTestClient();
            Assert.AreEqual(signatureToVerify.Hash, client.DvsCreateDocumentHash(document));

            var url = client.GetAuthorizationRequestUrlAsync(Endpoint).Result;
            var resp = client.DvsVerifySignatureAsync(signatureToVerify, ts).Result;

            Assert.IsTrue(resp.IsSignatureValid);
            Assert.AreEqual(VerificationStatus.ValidSignature, resp.Status);
        }
        #endregion

        #region Methods
        private string GenerateSignature(string document)
        {
            var mfaClientLocation = Directory.GetParent(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)).Parent.FullName;
            var pin = "1111";
            var email = "asd@example.com";
            var deviceName = "test";

            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.CreateNoWindow = true;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardInput = true;
            startInfo.RedirectStandardOutput = true;
            // note that appveyor adds mfaclient.exe to the MiraclAuthenticationTests directory when build
            startInfo.FileName = mfaClientLocation + "\\mfaclient.exe";
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.Arguments = string.Format("-a \"{0}\" --path=\"{1}\\.identities\" -q auth register --email=\"{2}\" --pin=\"{3}\" --device-name=\"{4}\" --client-id=\"{5}\" --client-redirect-uri=\"{6}\"",
                                                Endpoint, mfaClientLocation, email, pin, deviceName, ClientId, ClientRedirectUri);

            using (Process authRegister = Process.Start(startInfo))
            {
                authRegister.StandardInput.NewLine = "\n";
                authRegister.StandardInput.WriteLine(); // hit ENTER to activate identity
                authRegister.StandardInput.Flush();
                authRegister.WaitForExit();

                Assert.That(authRegister.ExitCode, Is.EqualTo(0));
            }

            startInfo.Arguments = string.Format("-a \"{0}\" --path=\"{1}\\.identities\" -q dvs register --email=\"{2}\" --pin=\"{3}\" --device-name=\"{4}\" --client-id=\"{5}\" --client-secret=\"{6}\" --client-redirect-uri=\"{7}\" --num=\"1\"",
                                                Endpoint, mfaClientLocation, email, pin, deviceName, ClientId, ClientSecret, ClientRedirectUri);

            using (Process dvsRegister = Process.Start(startInfo))
            {
                dvsRegister.WaitForExit();
                Assert.That(dvsRegister.ExitCode, Is.EqualTo(0));
            }

            startInfo.Arguments = string.Format("--path=\"{0}\\.identities\" -q dvs sign --pin=\"{1}\" \"{2}\"", mfaClientLocation, pin, document);

            var s = "";
            using (Process generateSignature = Process.Start(startInfo))
            {
                generateSignature.StandardInput.NewLine = "\n";
                generateSignature.StandardInput.WriteLine(1); // select only the first dvs registered identity
                generateSignature.StandardInput.Flush();

                generateSignature.WaitForExit();
                Assert.That(generateSignature.ExitCode, Is.EqualTo(0));

                s = generateSignature.StandardOutput.ReadToEnd();
                s = s.Split(new string[] { "Choose your identity:" }, StringSplitOptions.RemoveEmptyEntries)[1].Trim();
            }

            return s;
        }

        private MiraclClient InitIntegrationTestClient()
        {
            var options = new MiraclAuthenticationOptions();
            options.ClientId = ClientId;
            options.ClientSecret = ClientSecret;
            options.PlatformAPIAddress = Endpoint;

            var client = new MiraclClient(options);
            return client;
        }
        #endregion
    }
}
