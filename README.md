# maas-sdk-dotnet-v2

[![Build status](https://ci.appveyor.com/api/projects/status/qnl8i9kg46hu4t0m/branch/master?svg=true)](https://ci.appveyor.com/project/miracl/maas-sdk-dotnet-v2/branch/master)

[![Coverage Status](https://coveralls.io/repos/github/miracl/maas-sdk-dotnet-v2/badge.svg?branch=master)](https://coveralls.io/github/miracl/maas-sdk-dotnet-v2?branch=master)

* **category**:    SDK
* **copyright**:   2019 MIRACL UK LTD
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

`CLIENT_ID` and `CLIENT_SECRET` are obtained from [MIRACL server](https://trust.miracl.cloud/) and are unique per application.

### Authorization flow

If the user is not authorized, (s)he should scan the qr barcode with his/her phone app and authorize on the MIRACL server. You need to have a login button on your view page:

```
<input type="submit" value="Login" />
 ```
which when clicked should redirects you to the Miracl platform for authorization:
```
var authorizationUri = await client.GetAuthorizationRequestUrlAsync(WebAppAbsoluteUri); 
return Redirect(authorizationUri);
```
or use the following method for RP initiated authorization (see [Authorization Flow section](https://github.com/miracl/maas-sdk-dotnet-v2/#authorization-flow) for more details):
```
string authUri = await client.GetRPInitiatedAuthUriAsync(email, device, WebAppAbsoluteUri);
return Redirect(authUri);
```

When the user is being authorized, (s)he is returned to the `redirect uri` defined at creation of the application in the server. The redirect uri should be the same as the one used by the `MiraclClient` object (constructed by the appBaseUri + `CallbackPath` value of the `MiraclAuthenticationOptions` object by default).

To complete the authorization the query of the received request should be passed to `client.ValidateAuthorizationAsync(Request.QueryString)`. This method will return `null` if user denied authorization or a response with the access token if authorization succeeded.

### Status check and user data

To check if the user has a token use `client.IsAuthorized()`. If so, `client.UserId`, `client.Email`, `client.MPinID` and `client.HashMPinID` will return additional user data after `client.GetIdentityAsync(tokenResponse)` is executed which itself returns the claims-based identity for granting a user to be signed in.
If `null` is returned, the user is not authenticated and client needs to be authorized once more to access the required data.

Use `client.ClearUserInfo(false)` to drop user identity data.

Use `client.ClearUserInfo()` to clear user authorization status.

### Use PrerollId

In order to use the PrerollId functionality in your web app, you should have an input where the user to enter it to:
```	
<input type="email" id="email" name="email" placeholder="Email Address (Preroll Id)" />
```
Its value should be added as part of the authorization url query string as follows:
```
var authorizationUri = await client.GetAuthorizationRequestUrlAsync(WebAppAbsoluteUri);
if (!string.IsNullOrEmpty(email))
{
    authorizationUri += "&prerollid=" + email;
}
return Redirect(authorizationUri);
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

There are two methods for verification of an identity when registering it to the Platform:
 - standard email verification - the user enters the identity email, receives an email with a link to our Platform which, after a click, verifies the identity
 - custom verification - the user starts the identity registration, the RP calls `GetRPInitiatedAuthUriAsync` method which initiates the identity activation and then continue to setup PIN
   - `GetRPInitiatedAuthUriAsync` - initiates the identity activation and returns the authentication url the RP should redirects to in order to continue the RP initiated identity registration PIN setup

 The field Verification Method in the Platform customer settings is responsible for setting the verification method type.

## Samples

Replace `CLIENT_ID` and `CLIENT_SECRET` in the `web.config` file with your valid credential data from the [MIRACL server](https://trust.miracl.cloud/). `baseUri`, which is passed to the `MiraclClient.GetAuthorizationRequestUrlAsync` method, should be the uri of your web application.
Note that the redirect uri, if not explicitly specified in the `MiraclAuthenticationOptions`, is constructed as `baseUri\login` (the default value of the `CallbackPath` property is `\login`) and it should be passed to the MIRACL server when requiring authentication credential.

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
