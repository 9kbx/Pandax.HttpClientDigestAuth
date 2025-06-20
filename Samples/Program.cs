
using Pandax.HttpClientDigestAuth;

var username = "root";
var password = "root";

Console.Write("type your IP address:");
var ip = Console.ReadLine()!.Trim();

var client = new HttpClient();
var request = new HttpRequestMessage(HttpMethod.Get, $"http://{ip}/cgi-bin/get_system_info.cgi");
var response = await client.SendWithDigestAuthAsync(request, username, password);
Console.WriteLine(response.StatusCode);
Console.WriteLine(await response.Content.ReadAsStringAsync());
