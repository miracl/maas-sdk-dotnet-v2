# maas-sdk-dotnet-v2

* **category**:    SDK
* **copyright**:   2017 MIRACL UK LTD
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

If the user is not authorized, (s)he should scan the qr barcode with his/her phone app and authorize on the MIRACL server. This could be done as pass the authorize uri to the qr bacode by `ViewBag.AuthorizationUri = client.GetAuthorizationRequestUrl(baseUri)` on the server and use it in the client with the following code:

```
<a id="btmpin"></a>

@section scripts{
<script src="<<Insert correct mpad url here>>" data-authurl="@ViewBag.AuthorizationUri" data-element="btmpin"></script>
}
```
Please refer to your distributor-specific documentation to find the correct url for the mpad.js `script src`

When the user is being authorized, (s)he is returned to the `redirect uri` defined at creation of the application in the server. The redirect uri should be the same as the one used by the `MiraclClient` object (constructed by the appBaseUri + `CallbackPath` value of the `MiraclAuthenticationOptions` object by default).

To complete the authorization the query of the received request should be passed to `client.ValidateAuthorization(Request.QueryString)`. This method will return `null` if user denied authorization or a response with the access token if authorization succeeded.

### Status check and user data

To check if the user has token use `client.IsAuthorized()`. If so, `client.UserId` and `client.Email` will return additional user data after `client.GetIdentity(tokenResponse)` is executed which itself returns the claims-based identity for granting a user to be signed in.
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

## Samples

Replace `CLIENT_ID` and `CLIENT_SECRET` in the `web.config` file with your valid credential data from the MIRACL server. `baseUri` which is passed to the `MiraclClient.GetAuthorizationRequestUrlAsync` method should be the uri of your web application.
Note that the redirect uri, if not explicitly specified in the `MiraclAuthenticationOptions`, is constructed as `baseUri\login` (the default value of the `CallbackPath` property is `\login`) and it should be passed to the MIRACL server when requiring authentication credential.

* `MiraclAuthenticationApp` demonstrates the usage of `MiraclClient` to authenticate to the MIRACL server

## Sample Endpoints
The sample handles the following requests in order to serve as an authenticator for a mobile app:
* POST /authzurl
 This returns an http status of OK and data in the following json format:
```
{
    "authorizeURL": "<- The authorization url ->"
} 
```
* POST /authtoken
This endpoint receives the Authorization Code and User ID in the following format:
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
