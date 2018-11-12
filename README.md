# maas-sdk-dotnet-v2

[![Build status](https://ci.appveyor.com/api/projects/status/5223lully3vwgmxe/branch/appveyor?svg=true)](https://ci.appveyor.com/project/Miracl/maas-sdk-dotnet-v2/branch/appveyor)

[![Build status](https://ci.appveyor.com/api/projects/status/5223lully3vwgmxe?svg=true)](https://ci.appveyor.com/project/Miracl/maas-sdk-dotnet-v2)

[![Coverage Status](https://coveralls.io/repos/github/miracl/maas-sdk-dotnet-v2/badge.svg?branch=master)](https://coveralls.io/github/miracl/maas-sdk-dotnet-v2?branch=master)

* **category**:    SDK
* **copyright**:   2018 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/maas-sdk-dotnet-v2

## Description

.NET version of the Software Development Kit (SDK) for MPin-As-A-Service (MAAS).

## Setup

1. Download or Clone the project
1. Open `Authentication.sln` with Visual Studio and build
1. Reference the `MiraclAuthentication` project in your ASP.NET project so you could authenticate to the MIRACL server

## Dependencies

MIRACL .NET SDK has the following dependencies:

1. .NET framework 4.5.2 and above
1.  MS Visual Studio 2013 and above
1.  [IdentityModel2](https://www.nuget.org/packages/IdentityModel/)

# Miracl API

## Details and usage for authentication

All interaction with API happens through a `MiraclClient` object. Each application needs to construct an instance of `MiraclClient`.

### Initialization
To start using Miracl API, `MiraclClient` should be initialized. It can be done when needed or at application startup. `MiraclAuthenticationOptions` class is used to pass the authentication credentials and parameters.

```
client = new MiraclClient(new MiraclAuthenticationOptions
{
    ClientId = "CLIENT_ID" ,
    ClientSecret = "CLIENT_SECRET"
});
```

`CLIENT_ID` and `CLIENT_SECRET` are obtained from MIRACL server and are unique per application.

### Authorization flow

If the user is not authorized, (s)he should scan the qr barcode with his/her phone app and authorize on the MIRACL server. This could be done as pass the authorize uri to the qr bacode by `ViewBag.AuthorizationUri = await client.GetAuthorizationRequestUrlAsync(baseUri)` on the server and use it in the client with the following code:

```
<a id="btmpin"></a>

@section scripts{
<script src="<<Insert correct mpad url here>>" data-authurl="@ViewBag.AuthorizationUri" data-element="btmpin"></script>
}
```
Please refer to your distributor-specific documentation to find the correct url for the mpad.js `script src`

When the user is being authorized, (s)he is returned to the `redirect uri` defined at creation of the application in the server. The redirect uri should be the same as the one used by the `MiraclClient` object (constructed by the appBaseUri + `CallbackPath` value of the `MiraclAuthenticationOptions` object by default).

To complete the authorization the query of the received request should be passed to `client.ValidateAuthorizationAsync(Request.QueryString)`. This method will return `null` if user denied authorization or a response with the access token if authorization succeeded.

### Status check and user data

To check if the user has token use `client.IsAuthorized()`. If so, `client.UserId` and `client.Email` will return additional user data after `client.GetIdentityAsync(tokenResponse)` is executed which itself returns the claims-based identity for granting a user to be signed in.
If `null` is returned, the user is not authenticated or the token is expired and client needs to be authorized once more to access required data.

Use `client.ClearUserInfo(false)` to drop user identity data.

Use `client.ClearUserInfo()` to clear user authorization status.

### Use PrerollId

In order to use PrerollId functionality in your web app, you should set `data-prerollid` parameter with the desired preroll id to the data element passed for authentication:
```
<a id="{{buttonElementID}}" data-prerollid="{{prerollID}}></a>
```

In the current app this could be achieved with the following code:
```
<p>
	<a id="btmpin"></a>
</p>
<p>
	@Html.CheckBox("UsePrerollId") &nbsp; Use PrerollId login
	<div hidden="hidden">
		<label for="PrerollId" id="lblPrerollId">PrerollId</label>:
		<br />
		@Html.TextBox("PrerollId", string.Empty, new { style = "width:500px" })
	</div>
</p>

<script>
	$("#UsePrerollId").change(
	function () {
		var prerollIdContainer = $("#PrerollId").parent();
		prerollIdContainer.toggle();
		if (prerollIdContainer.is(":visible")) {
			$('#PrerollId').change(function (event) {
				var prerollIdData = document.getElementById('PrerollId').value;
				$('#btmpin').attr("data-prerollid", prerollIdData);
			});

		}
		else {
			$('#btmpin').removeAttr("data-prerollid");
		}
	});
</script>
```

### DVS flow

DVS (designated verifier signature) scheme allows a client entity to sign a message/document (an important transaction) which could be verified only by the designated verifier.
After the client (mobile) app generates the message, it sends it to the server (banking) which calls `MiraclClient.DvsCreateDocumentHash` method to create its hash using SHA256 hashing algorithm. Using the document hash the server creates an authorization token which is returned to the client app. Then the client app should create its signature and send the authorization token to verify the validity of the provided PIN. If the PIN is valid the client should proceed and pass the created signature to the server. The server has to create a `Signature` object and pass it to the `MiraclClient.DvsVerifySignatureAsync` method together with the epoch time (in seconds) of the signature creation (timestamp). The `MiraclClient` object retrieves the DVS Public Key from the MFA Platform where the DVS service runs and verifies the signature with it. The `Signature` object should have the following properties:
- `Hash` - the hash of the signed document
- `MpinId` - the M-Pin ID used to generate the signature
- `U` - the random commitment generated by the user
- `V` - the proof of the signature
- `PublicKey` - the user public key used in the key-escrow less scheme. Only if key-escrow less scheme is supported.

### Identity Registration Verification flow

There are different methods for verification of an identity when registering it to the Platform
- standard email verification - the user enters the identity email, receives an email with a link to our Platform which, after a click, verifies the identity
- custom email verification - the user enters the identity email, receives an email with a link to the Relying Party app where could be a custom logic for identity verification
- full custom verification which supports two user notification types
		- push - after the user has started the identity registration, the Platform sends a request to the Verification URL set by the customer in his/her Platform account settings where the identity is verified and activated for further PIN setup
		- pull - after the user has started the identity registration, the Relying Party application sends a request to the Platform to know if a registration for this identity has started. If so, a custom logic for its validating could be applied before activating it and continuing to setup PIN

There are fields in the Platform customer settings for setting up the Verification Method, the New User Notification Type (if a Full Custom method is set) and one for the Verification URL (if a Full Custom Push verification method used).
The methods which the Relying Party application should use to facilitate these operations are as follows:
- `GetIdentityInfoAsync` - used to require identity information per its `hashMPinId` and `activateKey`
- `ActivateIdentityAsync` - activates the identity in the Platform and the user could continue its registration and setup a PIN
- `HandleNewIdentityPushAsync` - validates the request from the Platform when Full Custom Verification with Push type used and return an `Identity` object
- `HandleNewIdentityPullAsync` - requests from the Platform if there is a started registration for the specified identity id and returns an `Identity` for it if so
- `ParseCustomEmailQueryString` - parses the query string for the Custom Email Verification and returns an `IdentityActivationParams` object

## Samples

Replace `CLIENT_ID` and `CLIENT_SECRET` in the `web.config` file with your valid credential data from the MIRACL server. `baseUri`, which is passed to the `MiraclClient.GetAuthorizationRequestUrlAsync` method, should be the uri of your web application.
Note that the redirect uri, if not explicitly specified in the `MiraclAuthenticationOptions`, is constructed as `baseUri\login` (the default value of the `CallbackPath` property is `\login`) and it should be passed to the MIRACL server when requiring authentication credential.
You have to setup the mpad.js url in the Views/Home/Index.cshtml too as explained in the [Authorization Flow section](https://github.com/miracl/maas-sdk-dotnet-v2/#authorization-flow).

* `MiraclAuthenticationApp` demonstrates the usage of `MiraclClient` to authenticate to the MIRACL server
* `MiraclDvsSigningApp` demonstrates the [DVS flow](https://github.com/miracl/maas-sdk-dotnet-v2/#dvs-flow) described above
* `MiraclIdentityVerificationApp` demonstrates the verification flows of an [identity registration](https://github.com/miracl/maas-sdk-dotnet-v2/#identity-registration-verification-flow) described above
* `demo` is used for integration testing and is part of a separate solution (`Integration.sln`) and it is not supposed to be run manually

## Sample Endpoints
The `MiraclAuthenticationApp` sample handles the following requests in order to serve as an authenticator for a mobile app:
* POST `/authzurl`
 This returns an http status of OK and data in the following json format:
```
{
    "authorizeURL": "<- The authorization url ->"
}
```
* POST `/authtoken`
This endpoint authenticates by Authorization Code and User ID, passed in the following format:
```
{
    "code":"<- the authorization code to validate with ->",
    "userID":"<- the authorized email to be verified ->"
}
```
The http status code of the response corresponds to the status of the authentication.

## Setting-up outbound HTTP Proxy Server

In order to make the SDK and the Sample Web App work using a proxy server, you should setup such using the Windows Internet configuration options:

1. Go to _Control Panel_ -> _Network and Internet_ -> _Internet Options_
1. Select the _Connections_ tab and the click the _LAN Settings_ button
1. Select the option _Use a proxy server for your LAN_ and specify the desired proxy server _Address_ and _Port_
1. Click the _OK_ button

After this configuration, the SDK and the Sample app should work through the specified proxy server.

## MIRACL .NET SDK Reference

 MIRACL .NET SDK library is based on the following libraries:

* [IdentityModel2](https://github.com/IdentityModel/IdentityModel2)
* [Microsoft.IdentityModel.Protocol.Extensions](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
* [Microsoft.Owin.Security](http://www.nuget.org/packages/Microsoft.Owin.Security/)
