<%@ Page Language="C#" Async="true" AutoEventWireup="true" CodeBehind="login.aspx.cs" Inherits="WebFormApp1.login" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
    <script type="text/javascript" src="Scripts/jquery-3.4.1.min.js"></script>
</head>
<body>
    <form id="form1" runat="server">
        <asp:HiddenField ID="platformApi" runat="server" />
        <asp:HiddenField ID="clientID" runat="server" />
        <asp:HiddenField ID="redirectURI" runat="server" />
        <div>
            <br />
            <div id="dvsRegisterResponse">
                <span>After you have been successfully authenticated you could register the identity to the DVS service in order to sign documents with it.
            <br />
                    Please, press the button to proceed.
                </span>
            </div>
            <br />
            <div id="dvsRegister">
                <input type="button" class="btn btn-primary" onclick="dvsRegister()" value="DVS register Input" />
            </div>
            <div id="dvsSign" class="hidden">
                <input type="button" class="btn btn-danger" onclick="dvsRemoveIdentity()" value="Remove signing identity" />
                <br />
                <br />
                <label for="doc">Enter text to be signed: </label>
                <br />
                <textarea id="doc" style="margin-bottom: 10px; margin-top: 5px" rows="4" cols="50"></textarea>
                <br />
                <input type="button" class="btn btn-primary" onclick="dvsSign($('#doc').val())" value="Sign" />
                <div id="signature" class="hidden">
                    <br />
                    <strong>Signature:</strong>
                    <pre id="signatureData"></pre>
                </div>
                <br />
                <div id="verificationResult" class="hidden">
                    <strong>Verification result:</strong>
                    <pre></pre>
                </div>
            </div>
        </div>

        <hr />
        <span>If you want to logout, press the button.</span>
        <br />
        <asp:Button runat="server" ID="LogoutBtn" OnClick="LogoutBtn_Click" Text="Logout" />

        <hr />
        <span>You have been authenticated with identity
            <asp:Label Font-Bold="true" ID="userId" runat="server" />
            which has the following data.</span>
        <br />
        <p>
            <strong>Access token:</strong>
            <br />
            <asp:TextBox ID="accessTokenTB" runat="server" TextMode="MultiLine" Height="120" Width="200"></asp:TextBox>
        </p>
    </form>
       
    <link rel="stylesheet" type="text/css" href="https://cdn.mpin.io/dvs/css/dvs.css" media="screen" />
    <script type="text/javascript" src="https://cdn.mpin.io/dvs/dvs.client.min.js"></script>
    <script type="text/javascript">

        var userId = '<%=userId.Text %>';
        var dvs = new DVS({
            userId: userId,
            server: '<%=platformApi.Value %>',
            clientId: '<%=clientID.Value %>',
            redirectURI: '<%=redirectURI.Value %>',
            pinPolicy: "different"
        });

        dvs.init(function () {
            dvs.hasIdentity(function success() {
                $("#dvsRegister").addClass("hidden");
                $("#dvsSign").removeClass("hidden");

                var element = $("#dvsRegisterResponse > span");
                element.removeClass("text-danger");
                element.html("An identity <b>" + userId + "</b> has been registered for DVS. Now you can sign documents with it.");
            }, function fail() {
                console.log("Not registered");
            });
        });

        function dvsRegister() {
            var successCb = function () {
                var element = $("#dvsRegisterResponse > span");
                element.removeClass("text-danger");
                element.html("An identity <b>" + userId + "</b> has been registered for DVS. Now you can sign documents with it.");

                $("#dvsRegister").addClass("hidden");
                $("#dvsSign").removeClass("hidden");
            };

            var errorCb = function (error) {
                var element = $("#dvsRegisterResponse > span");
                element.addClass("text-danger");
                element.html(error.message);
                console.log(error);
            };

            dvs.createIdentity(successCb, errorCb);
        }

        function dvsRemoveIdentity() {
            dvs.deleteIdentity(function () {
                console.info("Deleted identity");
                $("#dvsRegister").removeClass("hidden");
                $("#dvsSign").addClass("hidden");
            }, function () {
                console.error("Error while deleting identity");
            });
        }

        function dvsSign(doc) {
            $("#verificationResult").addClass("hidden");

            $.ajax({
                url: "CreateDocumentHashHandler.ashx",
                type: "POST",
                data: { document: doc },
                dataType: "json",
                cache: false,
                success: function (documentData) {
                    console.log("success" + documentData)
                    dvs.sign({
                        doc: doc,
                        hash: documentData.hash,
                        timestamp: documentData.timestamp
                    }, function success(signature) {
                        console.info("Successful signature:");
                        $("#signatureData").html(JSON.stringify(signature, null, 4));
                        $("#signature").removeClass("hidden");
                        dvsVerifySignature(signature, documentData);
                    }, function fail(error) {
                        console.error(error);
                    });
                }
            });
        }

        function dvsVerifySignature(signature, documentData) {
            $.ajax({
                url: "VerifySignatureHandler.ashx",
                type: "POST",
                data: { verificationData: JSON.stringify(signature), documentData: JSON.stringify(documentData) },
                dataType: "json",
                cache: false,
                success: function (res) {
                    $("#verificationResult").removeClass("hidden");
                    $("#verificationResult > pre").html(JSON.stringify(res, null, 4));
                }
            });
        }
    </script>


</body>
</html>
