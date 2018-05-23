using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ConsoleAppPowerBI
{
    class Program
    {
        static void Main(string[] args)
        {
            var app = new PowerBI();
            var token = app.getAccessToken();
            Console.WriteLine(token.access_token);
            Console.ReadLine();
        }
    }
    public class PowerBI
    {
        private static readonly string Username = "your_account";
        private static readonly string Password = "your_password";
        private static readonly string stsFqdn = "https://sts.contoso.com"; 
        private static readonly string ResourceUrl = "https://analysis.windows.net/powerbi/api";
        private static readonly string ClientId = "your_application_id";
        private static readonly string ClientSecret = "your_application_key";
        private static readonly string ApiUrl = "https://api.powerbi.com/";
        private static readonly string GroupId = "group-guid";
        private static readonly string ReportId = "report-guid";

        public GenericToken getAccessToken()
        {
            var resource = Uri.EscapeDataString(ResourceUrl);

            var uriId = Uri.EscapeDataString(ClientId);
            var uriSecret = Uri.EscapeDataString(ClientSecret);
            var uriUser = Uri.EscapeDataString(Username);

            //Before making the OAuth request against AAD we need a SAML assertion issued by ADFS to embed
            var assertion = getAssertion().Result;

            HttpClient client = new HttpClient();

            string requestUrl = $"https://login.microsoftonline.com/common/oauth2/token";
            var ua = new UserAssertion(assertion, "urn:ietf:params:oauth:grant-type:saml1_1-bearer", uriUser);

            UTF8Encoding encoding = new UTF8Encoding();
            Byte[] byteSource = encoding.GetBytes(ua.Assertion);
            string base64ua = Uri.EscapeDataString(Convert.ToBase64String(byteSource));
            string request_content = $"resource={resource}&client_id={uriId}&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml1_1-bearer&assertion={base64ua}&client_secret={uriSecret}&scope=openid";


            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            try
            {
                request.Content = new StringContent(request_content, Encoding.UTF8, "application/x-www-form-urlencoded");
            }
            catch (Exception x)
            {
                var msg = x.Message;
            }
            HttpResponseMessage response = client.SendAsync(request).Result;
            string responseString = response.Content.ReadAsStringAsync().Result;
            GenericToken token = JsonConvert.DeserializeObject<GenericToken>(responseString);

            return token;
        }

        private async Task<string> getAssertion()
        {
            HttpClient client = new HttpClient();

            string requestUrl = $"{stsFqdn}/adfs/services/trust/2005/usernamemixed";

            var saml = $"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' " +
                "xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>\r\n" +
                "<s:Header>\r\n<a:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>\r\n" +
                $"<a:MessageID>urn:uuid:{Guid.NewGuid().ToString()}</a:MessageID>\r\n" +
                "<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>\r\n" +
                $"<a:To s:mustUnderstand='1'>{stsFqdn}/adfs/services/trust/2005/usernamemixed</a:To>\r\n" +
                "<o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>" +
                $"<u:Timestamp u:Id='_0'><u:Created>{DateTime.UtcNow.ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'")}</u:Created>" +
                $"<u:Expires>{DateTime.UtcNow.AddMinutes(10).ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'")}</u:Expires>" +
                $"</u:Timestamp><o:UsernameToken u:Id='uuid-{Guid.NewGuid().ToString()}'>" +
                $"<o:Username>{Username}</o:Username><o:Password>{Password}</o:Password></o:UsernameToken></o:Security>\r\n" +
                "</s:Header>\r\n" +
                "<s:Body>\r\n" +
                "<trust:RequestSecurityToken xmlns:trust='http://schemas.xmlsoap.org/ws/2005/02/trust'>\r\n" +
                "<wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>\r\n" +
                "<a:EndpointReference>\r\n" +
                "<a:Address>urn:federation:MicrosoftOnline</a:Address>\r\n" +
                "</a:EndpointReference>\r\n" +
                "</wsp:AppliesTo>\r\n" +
                "<trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>\r\n" +
                "<trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>\r\n" +
                "</trust:RequestSecurityToken>\r\n</s:Body>\r\n</s:Envelope>";

            string request_content = saml;

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            try
            {
                request.Headers.Add("SOAPAction", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue");
                request.Headers.Add("client-request-id", Guid.NewGuid().ToString());
                request.Headers.Add("return-client-request-id", "true");
                request.Headers.Add("Accept", "application/json");
                request.Content = new StringContent(request_content, Encoding.UTF8, "application/soap+xml");
            }
            catch (Exception x)
            {
                var msg = x.Message;
            }
            HttpResponseMessage response = client.SendAsync(request).Result;
            string responseString = await response.Content.ReadAsStringAsync();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(responseString);
            var nodeList = doc.GetElementsByTagName("saml:Assertion");
            var assertion = nodeList[0].OuterXml;

            return assertion;
        }
    }

    public class GenericToken
    {
        public string token_type { get; set; }
        public string scope { get; set; }
        public string resource { get; set; }
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public string id_token { get; set; }
        public string expires_in { get; set; }
    }
}
