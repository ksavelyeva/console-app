using System;
using System.IO;
using System.Net;

public class AuthenticatedApplication
{
    private string _userName;
    private string _userPassword;
    private string _authServiceUrl;
    private string _appUrl;
    private CookieContainer _authCookie;

    public AuthenticatedApplication(string userName, string userPassword, string authServiceUrl, string appUrl)
    {
        _userName = userName;
        _userPassword = userPassword;
        _authServiceUrl = authServiceUrl;
        _appUrl = appUrl;
    }

    public void TryConnect()
    {
        TryLogin();

        if (IsAuthenticated())
        {
            Console.WriteLine("Authentication successful. Proceeding with other operations.");
        }
        else
        {
            Console.WriteLine("Authentication failed. Please check your credentials.");
        }
    }

    private void TryLogin()
    {
        var authData = @"{
            ""UserName"":""" + _userName + @""",
            ""UserPassword"":""" + _userPassword + @"""
        }";

        var request = CreateRequest(_authServiceUrl, authData);
        _authCookie = new CookieContainer();
        request.CookieContainer = _authCookie;

        using (var response = (HttpWebResponse)request.GetResponse())
        {
            if (response.StatusCode == HttpStatusCode.OK)
            {
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    var responseMessage = reader.ReadToEnd();
                    if (responseMessage.Contains("\"Code\":1"))
                    {
                        throw new UnauthorizedAccessException($"Unauthorized {_userName} for {_appUrl}");
                    }
                }

                string authName = ".ASPXAUTH";
                string authCookieValue = response.Cookies[authName].Value;
                _authCookie.Add(new Uri(_appUrl), new Cookie(authName, authCookieValue));
            }
        }
    }

    public bool IsAuthenticated()
    {
        var authCookieName = ".ASPXAUTH";
        var cookie = _authCookie.GetCookies(new Uri(_appUrl))[authCookieName];
        return cookie != null && !string.IsNullOrEmpty(cookie.Value);
    }

    private HttpWebRequest CreateRequest(string url, string requestData = null)
    {
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.ContentType = "application/json";
        request.Method = "POST";
        request.KeepAlive = true;
        if (!string.IsNullOrEmpty(requestData))
        {
            using (var requestStream = request.GetRequestStream())
            {
                using (var writer = new StreamWriter(requestStream))
                {
                    writer.Write(requestData);
                }
            }
        }
        return request;
    }

    // Method realizes protection from CSRF attacks: copies cookie, which contents CSRF-token 
    // and pass it to the header of the next request.
    private void AddCsrfToken(HttpWebRequest request)
    {
        var cookie = _authCookie.GetCookies(new Uri(_appUrl))["BPMCSRF"];
        if (cookie != null)
        {
            request.Headers.Add("BPMCSRF", cookie.Value);
        }
    }

    // Helper method to create a GET request.
    private HttpWebRequest CreateGetRequest(string url)
    {
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        request.Method = "GET";
        request.CookieContainer = _authCookie;
        request.KeepAlive = true;
        return request;
    }


    // Method to make an authenticated GET request to the specified URL.
    public string MakeAuthenticatedGetRequest(string url)
    {
        if (!IsAuthenticated())
        {
            Console.WriteLine("Not authenticated. Please call TryConnect() first to authenticate.");
            return null;
        }

        HttpWebRequest request = CreateGetRequest(url);
        AddCsrfToken(request);

        using (var response = (HttpWebResponse)request.GetResponse())
        {
            if (response.StatusCode == HttpStatusCode.OK)
            {
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    return reader.ReadToEnd();
                }
            }
            else
            {
                Console.WriteLine($"Failed to fetch data. Status Code: {response.StatusCode}");
                return null;
            }
        }
    }
}

public class Program
{
    public static void Main()
    {
        string filePath = "./data.txt";
        string authServiceUrl = "https://01195748-5-demo.creatio.com/ServiceModel/AuthService.svc/Login";
        string appUrl = "https://01195748-5-demo.creatio.com/0/odata/";
        string userName = "Supervisor";
        string userPassword = "Supervisor";

        AuthenticatedApplication app = new AuthenticatedApplication(userName, userPassword, authServiceUrl, appUrl);
        app.TryConnect();

        string odataUrl = "https://01195748-5-demo.creatio.com/0/odata/Contact?$top=1";
        string responseData = app.MakeAuthenticatedGetRequest(odataUrl);
        if (responseData != null)
        {
            File.WriteAllText(filePath, responseData);
            Console.WriteLine("Response data written to file: " + filePath);
        }
    }
}
