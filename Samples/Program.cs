
using Pandax.HttpClientDigestAuth;

var username = "root";
var password = "root";

var client = new HttpClient();
var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:5001");
var response = await client.SendWithDigestAuthAsync(request, username, password);
Console.WriteLine(response.StatusCode);
Console.WriteLine(await response.Content.ReadAsStringAsync());
