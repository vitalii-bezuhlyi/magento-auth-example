using System.Security.Cryptography;
using System.Text;
using System.Web;

/*
 * Here is a simple example of how to generate an OAuth 1.0 signature for a Magento API request.
 */

string httpMethod = "GET";
string url = string.Empty;
string oauthNonce = MagentoApiHelper.GenerateNonce();
string oauthTimestamp = MagentoApiHelper.GenerateTimestamp();
string consumerKey = string.Empty;
string consumerSecret = string.Empty;
string accessToken = string.Empty;
string accessTokenSecret = string.Empty;

string authorizationHeader = MagentoApiHelper.CreateAuthorizationHeader(httpMethod, url, consumerKey, oauthNonce, oauthTimestamp, accessToken, consumerSecret, accessTokenSecret);
Console.WriteLine("Authorization: " + authorizationHeader);

class MagentoApiHelper
{
    public static string GenerateOauthSignature(string httpMethod, Uri uri, Dictionary<string, string> oauthParams, string consumerSecret, string tokenSecret)
    {
        // Parse the query parameters from the URI
        var queryParams = HttpUtility.ParseQueryString(uri.Query);
        foreach (var key in queryParams.AllKeys)
        {
            oauthParams.Add(key, queryParams[key]);
        }

        // Step 1: Create the base string parameters sorted alphabetically by key
        var sortedParams = new SortedDictionary<string, string>(oauthParams);
        var parameterString = new StringBuilder();
        foreach (var param in sortedParams)
        {
            parameterString.Append($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(param.Value)}&");
        }
        parameterString.Length--;

        // Step 2: Create the signature base string
        string signatureBaseString = $"{httpMethod.ToUpper()}&{Uri.EscapeDataString(uri.GetLeftPart(UriPartial.Path))}&{Uri.EscapeDataString(parameterString.ToString())}";

        // Step 3: Create the signing key
        string signingKey = $"{Uri.EscapeDataString(consumerSecret)}&{Uri.EscapeDataString(tokenSecret)}";

        // Step 4: Generate the HMAC-SHA256 hash
        using (var hasher = new HMACSHA256(Encoding.ASCII.GetBytes(signingKey)))
        {
            byte[] hashBytes = hasher.ComputeHash(Encoding.ASCII.GetBytes(signatureBaseString));
            return Convert.ToBase64String(hashBytes);
        }
    }

    public static string CreateAuthorizationHeader(string httpMethod, string url, string oauthConsumerKey, string oauthNonce, string oauthTimestamp, string oauthToken, string consumerSecret, string tokenSecret)
    {
        string oauthSignatureMethod = "HMAC-SHA256";

        // Prepare OAuth parameters
        var oauthParams = new Dictionary<string, string>
        {
            { "oauth_consumer_key", oauthConsumerKey },
            { "oauth_nonce", oauthNonce },
            { "oauth_signature_method", oauthSignatureMethod },
            { "oauth_timestamp", oauthTimestamp },
            { "oauth_token", oauthToken }
        };

        // Generate the oauth_signature
        string oauthSignature = GenerateOauthSignature(httpMethod, new Uri(url), oauthParams, consumerSecret, tokenSecret);

        // Construct the Authorization header
        var authorizationHeader = new StringBuilder("OAuth ");
        foreach (var param in oauthParams)
        {
            authorizationHeader.AppendFormat("{0}=\"{1}\", ", param.Key, Uri.EscapeDataString(param.Value));
        }
        authorizationHeader.AppendFormat("oauth_signature=\"{0}\"", Uri.EscapeDataString(oauthSignature));

        return authorizationHeader.ToString();
    }

    public static string GenerateTimestamp()
    {
        return DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
    }

    public static string GenerateNonce()
    {
        return Guid.NewGuid().ToString("N");
    }
}