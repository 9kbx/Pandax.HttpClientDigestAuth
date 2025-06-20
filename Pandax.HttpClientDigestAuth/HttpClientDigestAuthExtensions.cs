using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Pandax.HttpClientDigestAuth;

public static class HttpClientDigestAuthExtensions
{
    // 请注意：在实际应用中，你可能需要一个更复杂的机制来管理 nonce-count (nc)
    // 因为它是针对客户端会话的，如果每次请求都创建一个新的 HttpClient 实例（在扩展方法内部或外部），
    // 并且服务器对 nc 有严格要求，那么这个简单的 int 递增可能不够。
    // 但是，对于许多服务器而言，只要在单次认证握手（即 401 后的重试）中正确递增即可。
    // 对于5000台矿机，每台矿机可能对应一个独立的 HttpClient 实例（或通过IHttpClientFactory管理），
    // 它们各自的 nonce-count 独立递增是合理的。

    // 内部帮助类，用于封装 Digest 认证逻辑
    private class DigestAuthenticator
    {
        private readonly string _username;
        private readonly string _password;
        private readonly Dictionary<string, string> _digestParameters = new Dictionary<string, string>();
        private int _nonceCount = 0; // 每个 DigestAuthenticator 实例的 nonce-count

        public DigestAuthenticator(string username, string password)
        {
            _username = username ?? throw new ArgumentNullException(nameof(username));
            _password = password ?? throw new ArgumentNullException(nameof(password));
        }

        public async Task<HttpRequestMessage> AuthenticateRequestAsync(HttpRequestMessage originalRequest,
            HttpResponseMessage unauthorizedResponse)
        {
            if (unauthorizedResponse == null ||
                unauthorizedResponse.StatusCode != System.Net.HttpStatusCode.Unauthorized ||
                !unauthorizedResponse.Headers.Contains("WWW-Authenticate"))
            {
                throw new ArgumentException(
                    "Provided response is not a 401 Unauthorized with WWW-Authenticate header.",
                    nameof(unauthorizedResponse));
            }

            string authenticateHeader = unauthorizedResponse.Headers.GetValues("WWW-Authenticate").FirstOrDefault();

            if (authenticateHeader == null ||
                !authenticateHeader.StartsWith("Digest", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "WWW-Authenticate header does not indicate Digest authentication.",
                    nameof(authenticateHeader));
            }

            ParseDigestHeader(authenticateHeader);

            if (!_digestParameters.ContainsKey("realm") || !_digestParameters.ContainsKey("nonce"))
            {
                throw new InvalidOperationException(
                    "Missing essential Digest authentication parameters (realm or nonce).");
            }

            string cnonce = GenerateCnonce();
            Interlocked.Increment(ref _nonceCount); // 递增 nonce-count
            string nonce = _digestParameters["nonce"];
            string nc = _nonceCount.ToString("X8"); // 格式化为 8 位十六进制
            string qop = _digestParameters.GetValueOrDefault("qop", ""); // 默认空字符串，以便兼容没有 qop 的情况

            string ha1 = CalculateHA1(_digestParameters["realm"]);
            string ha2 = await CalculateHA2(
                originalRequest.Method.ToString(),
                originalRequest.RequestUri.PathAndQuery,
                originalRequest.Content, // 传入请求体
                qop); // 传入qop

            string responseHash = CalculateResponse(
                nonce,
                nc,
                cnonce,
                qop,
                ha1,
                ha2);

            // 构建新的 Authorization 头
            string authorizationHeaderValue = BuildAuthorizationHeader(
                originalRequest.RequestUri.PathAndQuery,
                cnonce,
                nc,
                responseHash);

            // 克隆原始请求并添加新的 Authorization 头
            var newRequest = new HttpRequestMessage(originalRequest.Method, originalRequest.RequestUri);

            foreach (var header in originalRequest.Headers)
            {
                newRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (originalRequest.Content != null)
            {
                // 确保克隆请求体，以便重新发送
                newRequest.Content = await CloneHttpContent(originalRequest.Content);
            }

            newRequest.Headers.Authorization = new AuthenticationHeaderValue("Digest", authorizationHeaderValue);

            return newRequest;
        }

        // --- 辅助方法（与 DelegatingHandler 中的相同） ---

        private void ParseDigestHeader(string header)
        {
            _digestParameters.Clear();
            var matches = Regex.Matches(header, @"(\w+)\s*=\s*(?:""([^""]*)""|(\S+))");

            foreach (Match match in matches)
            {
                string key = match.Groups[1].Value;
                string value = match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Value;
                _digestParameters[key] = value.Trim();
            }
        }

        private string CalculateHA1(string realm)
        {
            string ha1Input = $"{_username}:{realm}:{_password}";

            return GetMD5Hash(ha1Input);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="method"></param>
        /// <param name="uri"></param>
        /// <returns></returns>
        /// <remarks>
        /// qop (Quality of Protection) 的影响： Digest 认证规范中有一个 qop 参数，它可能影响 HA2 的计算：<br/>
        /// qop="auth"：这是最常见的，只对请求行（方法和 URI）进行哈希，不包括请求体。<br/>
        /// qop="auth-int"：这表示 "认证和完整性保护"，它要求 HA2 的计算包含请求体的哈希值。这是为了确保请求体在传输过程中没有被篡改。
        /// </remarks>
        private async Task<string> CalculateHA2(string method, string uri, HttpContent requestContent, string qop)
        {
            string ha2Input;

            if (qop == "auth-int" && requestContent != null)
            {
                // 对于 auth-int，需要包含请求体的 MD5 哈希
                // 注意：这里需要再次读取请求体内容，确保它是可重复读取的
                // CloneHttpContent 已经处理了 MemoryStream，所以这里可以安全地再次读取
                string bodyHash = "";

                if (requestContent != null)
                {
                    // 创建一个临时的 MemoryStream 来读取内容，不影响原始内容流
                    using (var ms = new System.IO.MemoryStream())
                    {
                        await requestContent.CopyToAsync(ms);
                        ms.Position = 0; // 重置流的位置以便 GetMD5Hash 读取
                        bodyHash = GetMD5Hash(ms.ToArray()); // 对字节数组进行哈希
                    }
                }

                ha2Input = $"{method}:{uri}:{bodyHash}";
            }
            else
            {
                // 对于 auth 或没有 qop，只包含方法和 URI
                ha2Input = $"{method}:{uri}";
            }

            return GetMD5Hash(ha2Input);
        }

        private string CalculateResponse(string nonce, string nc, string cnonce, string qop, string ha1, string ha2)
        {
            string responseInput;

            if (qop == "auth" || qop == "auth-int")
            {
                responseInput = $"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}";
            }
            else
            {
                responseInput = $"{ha1}:{nonce}:{ha2}";
            }

            return GetMD5Hash(responseInput);
        }

        private string GetMD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }

                return sb.ToString();
            }
        }

        // GetMD5Hash 的一个重载，用于处理字节数组
        private string GetMD5Hash(byte[] inputBytes)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }

                return sb.ToString();
            }
        }

        private string GenerateCnonce()
        {
            return Guid.NewGuid().ToString("N").Substring(0, 16);
        }

        private string BuildAuthorizationHeader(string uri, string cnonce, string nc, string responseHash)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append($"username=\"{_username}\", ");
            sb.Append($"realm=\"{_digestParameters["realm"]}\", ");
            sb.Append($"nonce=\"{_digestParameters["nonce"]}\", ");
            sb.Append($"uri=\"{uri}\", ");

            if (_digestParameters.ContainsKey("qop") &&
                (_digestParameters["qop"] == "auth" || _digestParameters["qop"] == "auth-int"))
            {
                sb.Append($"qop=\"{_digestParameters["qop"]}\", ");
                sb.Append($"nc={nc}, ");
                sb.Append($"cnonce=\"{cnonce}\", ");
            }

            sb.Append($"response=\"{responseHash}\"");

            if (_digestParameters.ContainsKey("opaque"))
            {
                sb.Append($", opaque=\"{_digestParameters["opaque"]}\"");
            }

            return sb.ToString();
        }

        private async Task<HttpContent> CloneHttpContent(HttpContent originalContent)
        {
            if (originalContent == null)
                return null;

            var ms = new System.IO.MemoryStream();
            await originalContent.CopyToAsync(ms);
            ms.Position = 0;

            var clonedContent = new StreamContent(ms);

            foreach (var header in originalContent.Headers)
            {
                clonedContent.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return clonedContent;
        }
    }

    /// <summary>
    /// 使用 Digest 身份认证发送 HTTP 请求的扩展方法。
    /// </summary>
    /// <param name="client">HttpClient 实例。</param>
    /// <param name="request">要发送的 HttpRequestMessage。</param>
    /// <param name="username">用于 Digest 认证的用户名。</param>
    /// <param name="password">用于 Digest 认证的密码。</param>
    /// <returns>HttpResponseMessage。</returns>
    public static async Task<HttpResponseMessage> SendWithDigestAuthAsync(this HttpClient client,
        HttpRequestMessage request,
        string username,
        string password,
        CancellationToken cancellation = default)
    {
        // 1. 发送初始请求
        // 使用 HttpCompletionOption.ResponseHeadersRead 
        HttpResponseMessage response =
            await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);

        // 2. 检查是否需要 Digest 认证
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized &&
            response.Headers.Contains("WWW-Authenticate"))
        {
            string authenticateHeader = response.Headers.GetValues("WWW-Authenticate").FirstOrDefault();

            if (authenticateHeader != null &&
                authenticateHeader.StartsWith("Digest", StringComparison.OrdinalIgnoreCase))
            {
                // 创建一个临时的 DigestAuthenticator 实例来处理认证逻辑
                var authenticator = new DigestAuthenticator(username, password);

                // 获取认证后的新请求
                var authenticatedRequest = await authenticator.AuthenticateRequestAsync(request, response);

                // 在此处确保旧的响应体被读取或关闭，即使不使用 ResponseContentRead
                // 否则连接可能无法被释放或重用
                if (response.Content != null)
                {
                    // 尝试读取并丢弃内容，或者直接 Dispose
                    await response.Content.ReadAsByteArrayAsync(cancellation); // 强制读取所有内容并丢弃
                }

                // 确保旧的响应被处理或丢弃，避免资源泄露
                response.Dispose();

                // 3. 发送带有认证信息的新请求
                return await client.SendAsync(authenticatedRequest, cancellation);
            }
        }

        // 如果第一次请求不是 401 Unauthorized 或不是 Digest 认证
        // 且第一次请求使用了 ResponseHeadersRead，那么这里就需要确保将响应内容读取出来
        // 否则后续使用 response.Content 会因为连接已关闭或流未读取完毕而失败。
        // 或者，如果确定此时响应内容不会被消费，可以提前 Dispose。
        if (response.Content != null)
        {
            // 对于非 401 响应，我们假设它可能是正常响应，并且可能需要读取内容
            // 确保在返回之前，内容流是可用的或者已经读取完毕
            // 最简单的方式是让它按默认方式完成读取，或者明确读取它
            // 因为外部调用者可能期望获得一个完整的 HttpResponseMessage
            await response.Content.ReadAsByteArrayAsync(cancellation); // 强制读取所有内容

            // 为什么需要这样做？
            // 当您使用 ResponseHeadersRead 时，HttpClient 会在读取完响应头后就将 HttpResponseMessage 对象返回给您。
            // 此时，底层的网络连接仍然是打开的，并且响应体数据还在网络流中等待被读取。
            // - 如果后续没有读取这个响应体（或者没有正确处理 response.Content 的流），那么这个连接就可能永远不会被正确关闭和释放到连接池中，这会导致连接耗尽问题。
            // - 如果您在认证成功后直接返回了原始的 response 对象，而外部调用者又尝试读取 response.Content，那么他们可能会遇到问题，因为流可能已经关闭或处于不确定状态。
        }

        return response;
    }

    /// <summary>
    /// 简化 Get 请求的 Digest 认证扩展方法。
    /// </summary>
    public static Task<HttpResponseMessage> GetWithDigestAuthAsync(this HttpClient client,
        string requestUri,
        string username,
        string password,
        CancellationToken cancellation = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

        return client.SendWithDigestAuthAsync(request, username, password, cancellation: cancellation);
    }
}