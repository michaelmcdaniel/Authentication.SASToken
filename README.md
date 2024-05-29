# Authentication.SASToken
Authentication library to protect endpoints using Shared Access Signatures (SASToken)

SASTokens can be composed of unique identifier, version, roles [or permissions], signature, expiration, start time, resource, ip [or range] and/or scheme.  Signatures are generated from a secret using HMACSHA256 where the version describes the information used to populate the signature data.  In the simplest form, the signature includes the Uri and the expiration of the token.  The Id specifies which secret to use to generate the signature.  When validating, the server will take it's own information about the request and generate a signature to compare with what the client has sent.  Roles, resource, allowed ip addresses, and schemes can be used to add additional security to endpoints.

Tokens are verified using a **SASTokenKey** which contains all the properties of a SASToken with the addition of the Uri and secret used to generate the signature.  Generated secrets are 32 bytes, base64 encoded.

This implementation allows for tokens to be created using wildcard verification of the url path given at runtime using either header or query string.

#### Url Authentication Example
```
https://example.com/api/get-user?api-version=2024-01&sp=https%3A%2F%2Fexample.com%2Fapi%2F**&sig=yjqFaDKxaVBXLhNBIxl%2FhFjVJeEe1UUIzI%2F28LtdJ0U%3D&se=1716400963&skn=99333392-1132-402a-838e-b4962b05c67e
```
#### Header Authentication Example
```
GET https://example.com/api/get-user HTTP/1.1
Host: example.com
Authorization: SharedAccessSignature  api-version=2024-01&sp=https%3A%2F%2Fexample.com%2Fapi%2F**&sig=yjqFaDKxaVBXLhNBIxl%2FhFjVJeEe1UUIzI%2F28LtdJ0U%3D&se=1716400963&skn=99333392-1132-402a-838e-b4962b05c67e
```

## Rollover Guidance
In many cases, it best to add at least 2 SASTokenKeys for rollover purposes.  When you want to expire SASTokens, you can use the secondary SASTokenKey to issue updated tokens to clients. After all clients have been updated, simply remove the old SASTokenKey and add another for a future rollover.


## Wildcard paths
Path validation supports a wildcard character of an asterisk **\***. Single asterisk mean anything for a single segment, where as double asterick **\*\*** means match across one or more segments.  Path matching is case-insensitive.

#### Matching Examples
**url request:** /segment1/segment2/segment3

**matching SASTokenKey.Uri** 

**/segment1/segment2/segment3** - exact path match only\
**/segment1/segment2/segment\*** - match root segment '/segment1/segment2/' and 3rd segment must starts wit 'segment' *(only 3 segments allowed)*\
**/seg\*\*** - match any path starting with 'seg' *('/seg/' included)*\
**/\*\***  - match anything under root '/'\
**/\*\*/segment3**  - match all paths that end with 'segment3'\
**/\*/\*/segment3** - match any 2 segment names and ends with 'segment3' *(only 3 segments allowed)*\
**/segment1/\*\*** - match any endpoints under '/segment1' - *(at least 1 non-zero length sub-segment is required)*\
**/segment1/\*/\*** - match root '/segment1' and require 2 non-zero length sub-segments,  *(only 3 segments allowed)*\
**/segment1/segment2/\*** - match root segments '/segment1/segment2/' with any non-zero length 3rd segment *(only 3 segments allowed)*\
**/s\*/\*2/\*me\*** - first segment must start with 's', second segment must end with '2', and third segment must contain the word 'me' *(only 3 
segments allowed)*


# Configuration
Default implementation includes SASTokenKey Store for in-memory and app-configuration support, but it is extensible for other persistence.


## Using App Configuration

#### Configuration in appsettings.json
Add the following to your appsettings.json for a **SASTokenKey**.  This will be used to verify signatures.
*change the path to the url you wish to restrict*
```
"SASTokenKeys": {
        "99333392-1132-402a-838e-b4962b05c67e" : {
                "description":"Example",
                "path":"https://example.com/api/**",
                "version":"2024-01",
                "secret":"KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=",
                "expire":"0.00:05:00",
                "resource":"users",
                "ip":"0.0.0.0/0",
                "protocol":"https"
        }
}
```

Add the following to your program.cs (or startup.cs)
```
services.AddSASTokenStore_AppConfiguration();
```

## Using In-Memory Configuration
Add the following to your program.cs (or startup.cs)
```
builder.Services.AddSASTokenStore_InMemory();
var app = builder.Build();
app.UseSASTokenStore_InMemory((services,tokenStore)=>{
	tokenStore.SaveAsync(new SASTokenKey() {
		Id = "99333392-1132-402a-838e-b4962b05c67e",
		Name = "Example",
		Secret = "KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=",
		Uri = new Uri("https://example.com/api/**"),
		Version = SASTokenKey.VERSION_ABSOLUTE_URI,
		Expiration = TimeSpan.FromMinutes(5.0),
		Resource = "users",
		AllowedIPAddresses = "192.168.1.10",
		Protocol = "https,http"
	}).Result;
});
```


# Generating Tokens
Included is a console application **Authentication.SASToken.Generator** to generate new SASTokenKeys and SASTokens.  Running the console will allow you to create the required configuration and a valid SASToken for authentication.

**Running the Generator** 
```
C:\>Authentication.SASToken.Generator.exe
It is recommended to use a Guid for SASToken Ids.
  - A blank Id will create a new Guid id.
Enter SASTokenKey Id: 99333392-1132-402a-838e-b4962b05c67e
Enter a short description for the SASTokens: Example
Enter the Secret used to generated the SASToken signature.
  - Leave blank to generate a new secret
Enter Secret: KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=
Enter a relative or absolute url that this token will be valid for.
  - Wildcards are acceptable for path validation.
  - A blank url will allow all hosts and paths.
Enter url: https://example.com/api/**
Enter the version for the signature generation.  Leave blank to use default based on Uri
Allowed Versions:
        2024-04 = full uri in signature (Default)
        2024-05 = host only in signature
        2024-06 = uses a relative uri in the signature
Enter Version:
Using Version: 2024-04
Enter an expiration timespan that default tokens generated with this TokenSource will only be valid for.  Leave blank for max
Enter expiration timespan (d.HH:mm:ss): 0.00:05:00
This key can optionally restrict SASTokens by requiring a resource name. Leave blank to accept any value.
Enter the resource names (comma separated) that this key will protect: users
This key can optionally restrict SASTokens by requiring a scheme (ex. http,https.) Leave blank to accept any protocol.
Individual SASTokens can also further restrict these protocols.
Enter the protocol(s) - (comma separated) this key will allow: https
This key can optionally restrict SASTokens by only allowing certain ip address ranges. Comma separate for more than one range. formats:
  1.2.3.4  (single ip address)
  1.2.3.4/CIDR  (IP Address range using CIDR)
  1.2.3.0-1.2.3.255  (ip address range)
Individual SASTokens can also optionally include and override this range.
Enter the IP Address (or range) this key will allow: ::/0
appsettings.json format:
"SASTokenKeys": {
        "99333392-1132-402a-838e-b4962b05c67e" : {
                "description":"Example",
                "path":"https://example.com/api/**",
                "version":"2024-04",
                "secret":"KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=",
                "expire":"00:05:00",
                "resource":"users",
                "ip":"::/0",
                "protocol":"https"
        }
}
Roles are applied to a specific token and can be used during authentication. (not required)
Enter list of comma separated roles: Read,Write
The token requires a resource name in the authentication token. Valid resource names are:
  - users
Enter resource for the SASToken: users
Default Token: sv=2024-04&sr=users&sp=Read%2CWrite&sig=%2Fh6cXbnswIU6ur0UXrIDWwfQ1ru3Wfg7v5tM6KnGo1s%3D&se=1717010687&skn=99333392-1132-402a-838e-b4962b05c67e&spr=https&sip=%3A%3A%2F0
Enter a url to validate token (press enter to exit)
Url: https://example.com/api/get-user
Token Validated
...
```

You can copy and paste the appsettings.json format into your user secrets for later SASToken generation.

# Adding Authentication to Endpoints
There are several ways to protect endpoints using SASTokens. 

When a SASToken is authenticated using attributes or configuration, the HttpContext User is set to a ClaimsPrincipal that includes the details about the SASTokenKey used as well as roles encoded in the signature.

#### Issued Claims
| Type | Value | Cardinality |
| ---- | ----- | ----------- |
| [ClaimTypes.NameIdentifier](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.nameidentifier 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier') | SASTokenKey.Id | 1..1 |
| [ClaimTypes.Uri](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.uri 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/uri') | SASTokenKey.Uri | 1..1 |
| [ClaimTypes.Version](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.version 'http://schemas.microsoft.com/ws/2008/06/identity/claims/version') | SASToken.Version | 1..1 |
| [ClaimTypes.Expiration](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.expiration 'http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration') | SASToken.Expiration.ToUnixTimeSeconds() | 1..1 |
| [ClaimTypes.System](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.system 'http://schemas.microsoft.com/ws/2008/06/identity/claims/system') | SASToken.Resource | 1..N (comma separated) |
| [ClaimTypes.Role](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.role 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role') | SASToken.Roles.Split(',') | 0..N |

After adding the configuration, you can:
### Protect endpoints or entire controllers via attribute
```
// Allow all SASTokens matching - route must match SASTokenKey.Uri
[SASTokenAuthorization]
public class MyProtectedController() { ... } 

// Allow Admins or PowerUsers
[SASTokenAuthorization(new string[] { "Admin", "PowerUser" })]
public IActionResult GetUsers() => _impl.GetUsers().ToClientModel(); 
```

### Protect entire paths via configuration in program.cs (or startup.cs)
```
services.AddAuthentication().AddSASToken(options => {...});
```

### Inline Validation 
*Please note that inline validation does not assign the HttpContext.User*
```
// FROM HEADER
public async Task<IActionResult> GetUsersAsync([FromServices] ISASTokenKeyStore store)
{
	if (!await store.ValidateAsync(HttpContext)) return Forbid();
	return Json((await _sdk.GetUsersAsync()).ToClientModel()); 
}

// FROM QUERY STRING
public async Task<IActionResult> GetUsersAsync([FromServices] ISASTokenKeyStore store, [FromQuery(Name = "sv")] string v, [FromQuery] string sig, [FromQuery] long se, [FromQuery] string skn, [FromQuery] string? sp = null, [FromQuery] string? sip = null, [FromQuery] string? sr = null, [FromQuery] string? spr = null, [FromQuery] long st = 0)
{
	var token = new SASToken()
	{
		Id = skn,
		Expiration = DateTimeOffset.FromUnixTimeSeconds(se),
		Signature = sig,
		Roles = sp,
		Version = v,
		AllowedIPAddresses = sip,
		Protocol = spr,
		Resource = sr,
		StartTime = st == 0 ? DateTimeOffset.MinValue : DateTimeOffset.FromUnixTimeSeconds(st)
	};
	string[] anyUserInRoles = new string[] { "Admin", "PowerUsers" };
	var tokenKey = await _tokenStore.GetAsync(token);
	if (!tokenKey?.Validate(token, Request, anyUserInRoles, null, HttpContext.Connection.RemoteIpAddress, _logger) ?? false) return Forbid();

	return Json((await _sdk.GetUsersAsync()).ToClientModel()); 
}

```

