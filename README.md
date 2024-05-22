# Authentication.SASToken
Authentication library to protect endpoints using Shared Access Signatures (SASToken)

SASTokens are composed of version, resource, signature, expiration and Id.  Signatures are generated from a secret using HMACSHA256 where the version describes the information used to populate the signature data.  In the simplest form, the signature includes the [*endpoint*|*host*|*resource*] and the expiration of the token.  The Id specifies which secret to use to generate the signature.  When validating the server will take it's own information and generate a signature to compare with what the client has sent.

Tokens are verified using a **TokenSource** which contains all the properties of a SASToken with the addition of the secret used to generate the signature.

This implementation allows for tokens to be created using wildcard verification of the url path given at runtime using either header or query string.

#### Url Authentication Example
```
https://example.com/api/get-user?api-version=2024-01&sr=https%3A%2F%2Fexample.com%2Fapi%2F**&sig=yjqFaDKxaVBXLhNBIxl%2FhFjVJeEe1UUIzI%2F28LtdJ0U%3D&se=1716400963&skn=99333392-1132-402a-838e-b4962b05c67e
```
#### Header Authentication Example
```
GET https://example.com/api/get-user HTTP/1.1
Host: example.com
Authorization: SharedAccessSignature  api-version=2024-01&sr=https%3A%2F%2Fexample.com%2Fapi%2F**&sig=yjqFaDKxaVBXLhNBIxl%2FhFjVJeEe1UUIzI%2F28LtdJ0U%3D&se=1716400963&skn=99333392-1132-402a-838e-b4962b05c67e
```
## Wildcard paths
Path validation supports a wildcard character of an asterisk **\***. Single asterisk mean anything for a single segment, where as double asterick **\*\*** means match across one or more segments.  Path matching is case-insensitive.

#### Matching Examples
**url request:** /segment1/segment2/segment3

**matching TokenSource.Uri** 
**/segment1/segment2/segment3** - exact path match only
**/segment1/segment2/segment\*** - match root segment '/segment1/segment2/' and 3rd segment must starts wit 'segment' *(only 3 segments allowed)*
**/seg\*\*** - match any path starting with 'segm' *('/seg/' included)*
**/\*\***  - match anything under root '/'
**/\*\*/segment3**  - match all paths that end with 'segment3'
**/\*/\*/segment3** - match any 2 segment names and ends with 'segment3' *(only 3 segments allowed)*
**/segment1/\*\*** - match any endpoints under '/segment1' - *(at least 1 non-zero length sub-segment is required)*
**/segment1/\*/\*** - match root '/segment1' and require 2 non-zero length sub-segments,  *(only 3 segments allowed)*
**/segment1/segment2/\*** - match root segments '/segment1/segment2/' with any non-zero length 3rd segment *(only 3 segments allowed)*
**/s\*/\*2/\*me\*** - first segment must start with 's', second segment must end with '2', and third segment must contain the word 'me' *(only 3 segments allowed)*


# Configuration
Default implementation includes SASToken TokenSource Store for in-memory and app-configuration support, but it is extensible for other persistence.


## Using App Configuration

#### Configuration in appsettings.json
Add the following to your appsettings.json for a **TokenSource**.  This will be used to verify signatures.
*change the path to the url you wish to restrict*
```
"SASToken-Test": {
        "id":"99333392-1132-402a-838e-b4962b05c67e",
        "version":"2024-01",
        "expire":"0.00:05:00",
        "path":"https://example.com/api/**",
        "secret":"KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ="
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
app.UseSASTokenStore_InMemory((services,tokenSourceStore)=>{
	tokenSourceStore.SaveAsync(new TokenSource() {
		Id = new Guid("99333392-1132-402a-838e-b4962b05c67e"),
		Name = "Test",
		Secret = "KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=",
		Uri = new Uri("https://example.com/api/**"),
		Version = TokenSource.VERSION_ABSOLUTE_URI,
		Expiration = TimeSpan.FromMinutes(5.0)
	}).Result;
});
```


# Generating Tokens
Included is a console application **Authentication.SASToken.Generator** to generate new TokenSources and SASTokens.  Running the console will allow you to create the required configuration and a valid SASToken for authentication.

**Running the Generator** 
```
C:\>Authentication.SASToken.Generator.exe
Enter TokenSource Name: Test
Token exists in configuration. Use existing? (Y/N): n
Enter the Id (Guid format) for the TokenSource Id, leave blank for a new Id
Enter Id: 99333392-1132-402a-838e-b4962b05c67e
Enter the Secret for the TokenSource.  Leave blank to generate a new secret
Enter Secret:
Generated Secret: KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=
Enter the version for the signature generation.  Leave blank to use default
Known Versions:
        2024-01 = uses full uri (Default)
        2024-02 = host only in signature
        2024-03 = uses a relative uri in the signature
Enter Version: 2024-01
Enter a url that this token will only be valid for. Wildcards are acceptable for path validation.
Enter full url: https://example.com/api/**
Enter an expiration timespan that default tokens generated with this TokenSource will only be valid for.  Leave blank for max
Enter expiration timespan (d.HH:mm:ss): 0.0:5:0
Token Source: 99333392-1132-402a-838e-b4962b05c67e|https://example.com/api/**|KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=|2024-01
appsettings.json format:
"SASToken-Test": {
        "id":"99333392-1132-402a-838e-b4962b05c67e",
        "version":"2024-01",
        "expire":"00:05:00",
        "path":"https://example.com/api/**",
        "secret":"KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ="
}
Default Token: api-version=2024-01&sr=https%3A%2F%2Fexample.com%2Fapi%2F**&sig=yjqFaDKxaVBXLhNBIxl%2FhFjVJeEe1UUIzI%2F28LtdJ0U%3D&se=1716400963&skn=99333392-1132-402a-838e-b4962b05c67e
Enter a url to validate token (press enter to exit)
Url: https://example.com/api/get-user
Token Validated
...
```

You can copy and paste the appsettings.json format into your user secrets for later SASToken generation.

# Adding Authentication to Endpoints
There are several ways to protect endpoints using SASTokens.  After adding the configuration, you can:
### Protect endpoints or entire controllers via attribute
```
[SASTokenAuthorization]
public class MyProtectedController() { ... } 


[SASTokenAuthorization]
public IActionResult GetUsers() => _impl.GetUsers().ToClientModel(); 
```

2. Protect entire paths via configuration in program.cs (or startup.cs)
```
services.AddAuthentication().AddSASToken(options => {...});
```

3. Inline Validation 
```
// FROM HEADER
public async Task<IActionResult> GetUsersAsync([FromServices] ITokenSourceStore store)
{
	var token = Request.GetSASToken();
	if (!(await store.GetAsync(token))?.Validate(token, Request)??false) return Forbid();
	return (await _sdk.GetUsersAsync()).ToClientModel(); 
}

// FROM QUERY STRING
public async Task<IActionResult> GetUsersAsync([FromQuery(Name = "api-version")] string v, [FromQuery] string sr, [FromQuery] string sig, [FromQuery] long se, [FromQuery] string skn, [FromServices] ITokenSourceStore store)
{
	Guid sknId;
	Guid.TryParse(skn, out sknId);
	var token = new SASToken()
	{
		Id = sknId,
		Expiration = DateTimeOffset.FromUnixTimeSeconds(se),
		Signature = sig,
		Resource = sr,
		Version = v
	};
	if (!(await store.GetAsync(token))?.Validate(token, Request)??false) return Forbid();
	return (await _sdk.GetUsersAsync()).ToClientModel(); 
}

```

