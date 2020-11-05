<%@ Page Async="true" Title="Home Page" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="WebFormApp1._Default" EnableEventValidation="false" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">

    <div style="margin: 10px">
        <asp:PlaceHolder runat="server" ID="LoginForm" Visible="false">
            <asp:TextBox runat="server" ID="PrerollID" ToolTip="Preroll ID" />
            <asp:Button runat="server" ID="LoginBtn" OnClick="LoginBtn_Click" Text="Login" />
        </asp:PlaceHolder>
        <asp:Button runat="server" ID="LogoutBtn" OnClick="LogoutBtn_Click" Text="Logout" Visible="false" />
    </div>

</asp:Content>
