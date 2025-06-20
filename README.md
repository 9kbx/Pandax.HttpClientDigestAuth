# Pandax.HttpClientDigestAuth
C# HttpClient Digest 身份认证请求

```csharp
using Pandax.HttpClientDigestAuth;

var username = "root";
var password = "root";

var client = new HttpClient();
var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:5001");
var response = await client.SendWithDigestAuthAsync(request, username, password);
```