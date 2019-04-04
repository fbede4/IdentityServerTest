using IdentityModel.Client;
using IdentityServer.ViewModels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Client
{
    class Program
    {
        public static void Main(string[] args) => MainAsync().GetAwaiter().GetResult();

        private static async Task MainAsync()
        {
            var client = new HttpClient();

            string token = "";
            var uri = new Uri("http://localhost:5000/loginapi");
            HttpContent httpContent = new StringContent(JsonConvert.SerializeObject(new LoginApiDto
            {
                Username = "test@mailinator.com",
                Password = "password"
            }));
            httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var resp = await client.PostAsync(uri, httpContent);
            if (resp.IsSuccessStatusCode)
            {
                token = await resp.Content.ReadAsStringAsync();
            }
            Console.WriteLine(token);
            var apiClient2 = new HttpClient();
            var apiResponse2 = await apiClient2.GetAsync("http://localhost:5000/protected");
            if (!apiResponse2.IsSuccessStatusCode)
            {
                Console.WriteLine(apiResponse2.StatusCode);
            }
            else
            {
                var content = await apiResponse2.Content.ReadAsStringAsync();
                Console.WriteLine(content);
            }

            apiClient2 = new HttpClient();
            apiClient2.SetBearerToken(token);
            apiResponse2 = await apiClient2.GetAsync("http://localhost:5000/protected");
            if (!apiResponse2.IsSuccessStatusCode)
            {
                Console.WriteLine(apiResponse2.StatusCode);
            }
            else
            {
                var content = await apiResponse2.Content.ReadAsStringAsync();
                Console.WriteLine(content);
            }


            // discover endpoints from the metadata by calling Auth server hosted on 5000 port
            var disco = await client.GetDiscoveryDocumentAsync("http://localhost:5000");
            if (disco.IsError)
            {
                Console.WriteLine(disco.Error);
                return;
            }

            // request the token from the Auth server
            var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = "client",
                ClientSecret = "secret",
                Scope = "api1"
            });
            if (response.IsError)
            {
                Console.WriteLine(response.Error);
                return;
            }
            Console.WriteLine(response.Json);
            Console.WriteLine(response.RefreshToken);

            // call api
            var apiClient = new HttpClient();
            apiClient.SetBearerToken(response.AccessToken);

            var apiResponse = await apiClient.GetAsync("http://localhost:5000/protected");
            if (!apiResponse.IsSuccessStatusCode)
            {
                Console.WriteLine(apiResponse.StatusCode);
            }
            else
            {
                var content = await apiResponse.Content.ReadAsStringAsync();
                Console.WriteLine(JArray.Parse(content));
            }

            Console.Write($"\n\nShould get unauthorized error:\n");
            // call api
            apiClient = new HttpClient();
            apiResponse = await apiClient.GetAsync("http://localhost:5000/api/identity");
            if (!apiResponse.IsSuccessStatusCode)
            {
                Console.WriteLine(apiResponse.StatusCode);
            }
            else
            {
                var content = await apiResponse.Content.ReadAsStringAsync();
                Console.WriteLine(JArray.Parse(content));
            }

            // -----------------------------------------------------------------
            // Resource owner auth
            Console.WriteLine("------------------------------");
            Console.WriteLine("password auth");
            Console.WriteLine("------------------------------");

            // request token
            var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = "ro.client",
                ClientSecret = "secret",

                UserName = "alice",
                Password = "password",
                Scope = "api1"
            });

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                return;
            }

            Console.WriteLine(tokenResponse.Json);
        }
    }
}
