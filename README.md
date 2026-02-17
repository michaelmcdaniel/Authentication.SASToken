# Authentication.SASToken  
### ASP.NET Core Shared Access Signature (SAS) / HMAC Signed Request Authentication

[![NuGet](https://img.shields.io/nuget/v/mcdaniel.ws.AspNetCore.Authentication.SASToken.svg)](https://www.nuget.org/packages/mcdaniel.ws.AspNetCore.Authentication.SASToken)
[![NuGet Downloads](https://img.shields.io/nuget/dt/mcdaniel.ws.AspNetCore.Authentication.SASToken.svg)](https://www.nuget.org/packages/mcdaniel.ws.AspNetCore.Authentication.SASToken)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Authentication.SASToken** is an ASP.NET Core authentication and authorization middleware that implements **Shared Access Signature (SAS) style HMAC authentication** for APIs. It enables secure **signed URL** and **signed request** authorization using HMACSHA256 and shared secrets.

This library is designed for service-to-service API security, temporary access links, and object-level authorization scenarios where OAuth may be unnecessary. It provides short-lived, cryptographically signed tokens that can restrict access by path, resource, role, IP address, protocol, and signature scope.


- Expiration windows
- Start times
- Role/permission enforcement
- Resource scoping
- IP restrictions
- HTTP/HTTPS protocol restrictions
- Wildcard path matching (`*` / `**`)

This pattern is similar to Azure SAS tokens, pre-signed URLs, and other HMAC-based API authentication mechanisms.

---

## Table of Contents

- [Install](#install)
- [Quick Start](#quick-start)
- [Protecting Controllers or Endpoints](#protecting-controllers-or-endpoints)
- [Inline Validation](#inline-validation)
- [Token Formats](#token-formats)
- [HMAC Signature Versioning](#hmac-signature-versioning-sv)
- [Wildcard Path Matching](#wildcard-path-matching)
- [Resource Restrictions (`sr`)](#resource-restrictions-sr)
- [Claims Created on Authentication](#claims-created-on-authentication)
- [Generating Tokens](#generating-tokens)
- [Rollover Guidance](#rollover-guidance)
- [Security Recommendations](#security-recommendations)
- [When Not to Use This](#when-not-to-use-this)
- [License](#license)

---

# Install

```bash
dotnet add package mcdaniel.ws.AspNetCore.Authentication.SASToken
```

NuGet package:

`mcdaniel.ws.AspNetCore.Authentication.SASToken`

---

# Quick Start

## 1️⃣ Add a SASToken Key Store

The library includes:

- In-memory store
- AppSettings (`appsettings.json`) store
- File-based store

---

## Option A — appsettings.json Store (Recommended)

### Add configuration

```json
{
  "SASTokenKeys": {
    "99333392-1132-402a-838e-b4962b05c67e": {
      "description": "Example key",
      "path": "https://example.com/api/**",
      "version": "2024-04",
      "secret": "KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=",
      "expire": "0.00:05:00",
      "resource": "users",
      "ip": "::/0",
      "protocol": "https"
    }
  }
}
```

### Register the store

```csharp
builder.Services.AddSASTokenStore_AppConfiguration();
builder.Services.AddAuthentication().AddSASToken();
...
app.UseAuthentication();
app.UseAuthorization();

```

---

## Option B — In-Memory Store

```csharp
builder.Services.AddSASTokenStore_InMemory();

var app = builder.Build();

app.UseSASTokenStore_InMemory((services, tokenStore) =>
{
    tokenStore.SaveAsync(new SASTokenKey
    {
        Id = Guid.Parse("99333392-1132-402a-838e-b4962b05c67e"),
        Description = "Example key",
        Uri = new Uri("https://example.com/api/**"),
        Version = "2024-04",
        Secret = "KBpx2E2FH/WM2hEuDr82m0OyDyscyGcvU/4Zn40AOFQ=",
        Expiration = TimeSpan.FromMinutes(5),
        Resource = "users",
        IpRange = "::/0",
        Protocol = "https"
    });
});
```

---

## Option C — File Store
*Uses `IDataProtectionProvider` (if configured) to encrypt secrets at rest.*

```csharp
builder.Services.AddDataProtection();
builder.Services.AddSASTokenStore_File(options =>
{
    options.BasePath = "~/secrets";
    // options.FileNameFormat = "{Id}.json";
    // options.SearchPattern = "*.json";
    // options.PreCache = true;
    // options.SlidingCacheTime = TimeSpan.Zero;
    // options.RemoveEmptyFolders = true;
    // options.DefaultKeyName = Guid.Empty.ToString();
});
```

---

# Protecting Controllers or Endpoints

## Protect Entire Controller

```csharp
[SASTokenAuthorization]
[ApiController]
public class MyProtectedController : ControllerBase
{
    [HttpGet("/api/get-user")]
    public IActionResult GetUser() => Ok(new { ok = true });
}
```

---

## Protect Specific Actions with Roles

```csharp
[SASTokenAuthorization(new[] { "Admin", "PowerUser" })]
public IActionResult GetUsers()
{
    return Ok();
}
```

---

## Inline Validation

Inline validation does **not** assign `HttpContext.User`.

This approach is useful for SDK-style usage, minimal APIs, or when attribute-based authorization is not desired.

```csharp
// FROM HEADER
public async Task<IActionResult> GetUsersAsync([FromServices] ISASTokenKeyStore store)
{
    if (!await store.ValidateAsync(HttpContext))
        return Forbid();

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
	var tokenKey = await store.GetAsync(token);
	if (tokenKey == null ||
        !tokenKey.Validate(token, Request, anyUserInRoles, null, HttpContext.Connection.RemoteIpAddress, _logger)) 
        return Forbid();

	return Json((await _sdk.GetUsersAsync()).ToClientModel()); 
}
```

## Using SASToken with Existing Authentication (OAuth / JWT)

If your application already uses OAuth, JWT Bearer, or other authentication schemes with a global `[Authorize]` filter, you may need to explicitly allow anonymous access for SASToken-protected endpoints:

```csharp
[AllowAnonymous]
[SASTokenAuthorization]
[HttpGet("/api/users/{userId}")]
public IActionResult GetUser([SASTokenResource] Guid userId)
{
    ...
}
```
This ensures the request is not rejected by another authentication scheme before SASToken validation occurs.

Alternatively, you may configure SASToken as a named authentication scheme and apply it explicitly where needed.

---

# Token Formats

The library supports both **Authorization header tokens** and **query string tokens**.

## Recommended: Authorization Header (Preferred)

Using the `Authorization` header is the recommended and more secure approach.

**Why it is preferred:**


- Tokens are **not logged in URLs** (reverse proxies, web servers, analytics tools often log full URLs)
- Tokens are **not stored in browser history**
- Tokens are less likely to be accidentally shared via copied links
- Cleaner separation between routing and authentication
- Follows standard HTTP authentication patterns

Example:

```
GET https://example.com/api/get-user HTTP/1.1
Host: example.com
Authorization: SharedAccessSignature sv=2024-04&sr=users&sp=Read%2CWrite&sig=SIGNATURE&se=1716400963&skn=99333392-1132-402a-838e-b4962b05c67e&spr=https&sip=%3A%3A%2F0
```

---

## Query String Tokens

Primarily intended for:

- Signed URLs
- Temporary download links
- Environments where headers cannot be set

Example:

```
https://example.com/api/get-user?sv=2024-04&sr=users&sp=Read%2CWrite&sig=SIGNATURE&se=1716400963&skn=99333392-1132-402a-838e-b4962b05c67e&spr=https&sip=%3A%3A%2F0
```

> For production APIs, prefer the Authorization header unless signed URLs are required.

---

# HMAC Signature Versioning  (`sv`)

The `sv` (signature version) parameter controls **what parts of the request are included in the HMAC signature**.  
Different versions allow different levels of strictness and flexibility.

- **2024-04** *(Default — Most Secure)*  
  Signs the **full absolute URI** (scheme + host + full path).  
  - Most restrictive  
  - Token is bound to an exact endpoint  
  - Best for internal APIs where the domain is fixed  

- **2024-05**  
  Signs the **host only** (domain).  
  - Allows the token to be reused across multiple paths  
  - Still locked to a specific domain  
  - Useful when protecting many endpoints under the same API  

- **2024-06**  
  Signs the **relative URI (path only)**.  
  - Not bound to a specific host  
  - Useful behind reverse proxies, load balancers, or multi-environment deployments  
  - Most flexible, but least restrictive  

### Choosing a Version

| Version   | Flexibility | Security Strictness | Recommended Use |
|------------|------------|--------------------|------------------|
| 2024-04   | Low        | High               | Default for most APIs |
| 2024-05   | Medium     | Medium             | Multi-route APIs on same host |
| 2024-06   | High       | Lower              | Proxy / multi-environment scenarios |

> If unsure, use **2024-04**.


---

# Wildcard Path Matching

- `*` → Matches a single segment  
- `**` → Matches one or more segments  

Matching is case-insensitive.

### Example

Request:

```
/segment1/segment2/segment3
```

Valid key paths:

```
/segment1/segment2/segment3
/segment1/segment2/segment*
/seg**
/**
/**/segment3
/*/*/segment3
/segment1/**
```

---

# Resource Restrictions (`sr`)

SASTokens can optionally include a **resource identifier** (`sr`) that is validated during authentication.

A resource can represent either:

1. A **logical domain** (e.g., `users`, `orders`, `reports`)
2. A **specific resource instance** (e.g., a single user GUID)

This allows tokens to be bound not only to a route, but to the *exact object* being accessed.

---

## Example: Binding a Token to a Specific User (GUID)

Suppose you have an endpoint:

```
GET /api/users/{userId}
```

Where `userId` is a GUID.

You can require that the token include: `sr=3f2b2b6a-7b51-4e4d-b6aa-3f9a24c6c5b1`

```csharp
[HttpGet("/api/users/{userId}")]
public IActionResult GetUser([SASTokenResource] Guid userId)
{
    ...
}
```
The `[SASTokenResource]` attribute automatically binds the `sr` value from the token to the userId parameter and no additional validation logic is required in the controller.

During validation:
 - The token must include an `sr` value
 - The `sr` value must match the route parameter value
 - If they do not match, validation fails

This ensures the token is valid only for that specific user and cannot be reused for another \{userId}.

### Why this is useful

- Prevents a token issued for one user from being reused for another
- Enables signed-link style access to a single resource
- Supports temporary or delegated access to a specific object
- Strengthens object-level authorization


---

## Resource vs Path vs Roles

These controls operate at different layers:

| Restriction | Binds the token to… | Example |
|------------|----------------------|---------|
| Path (key `path`) | Route or route pattern | `/api/users/**` |
| Resource (`sr`) | Domain name or specific object id | `users` or `{userId-guid}` |
| Roles (`sp`) | Permissions granted within the resource | `Read`, `Write` |

> Path restriction limits *where* a token can be used.  
> Resource restriction limits *what specific object* it can access.  
> Roles limit *what actions* can be performed.

---

# Claims Created on Authentication

When a SASToken is authenticated using attributes or configuration, `HttpContext.User` is set to a ClaimsPrincipal that includes the details about the SASTokenKey used as well as roles encoded in the signature.

#### Issued Claims
| Type | Value | Cardinality |
| ---- | ----- | ----------- |
| [ClaimTypes.NameIdentifier](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.nameidentifier 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier') | SASTokenKey.Id | 1..1 |
| [ClaimTypes.Uri](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.uri 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/uri') | SASTokenKey.Uri | 1..1 |
| [ClaimTypes.Version](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.version 'http://schemas.microsoft.com/ws/2008/06/identity/claims/version') | SASToken.Version | 1..1 |
| [ClaimTypes.Expiration](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.expiration 'http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration') | SASToken.Expiration.ToUnixTimeSeconds() | 1..1 |
| [ClaimTypes.System](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.system 'http://schemas.microsoft.com/ws/2008/06/identity/claims/system') | SASToken.Resource | 1..N (comma separated) |
| [ClaimTypes.Role](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes.role 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role') | SASToken.Roles.Split(',') | 0..N |



---
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

---

# Rollover Guidance
For safe secret rotation:

1. Maintain at least two active keys  
2. Issue new tokens with the new key  
3. Wait for client refresh  
4. Remove the old key  
5. Add a standby key for next rotation  

This prevents downtime during secret rotation.

---

# Security Recommendations

- Always use HTTPS in production  
- Keep expiration times short (minutes, not days)  
- Rotate secrets regularly  
- Store secrets outside source control (User Secrets, Azure Key Vault, environment variables)  
- Restrict by IP and protocol when possible  

---

# When Not to Use This

This library is not intended to replace OAuth/OpenID Connect for:

- End-user authentication
- Browser-based login flows
- Third-party delegated authorization

It is best suited for service-to-service authentication and signed URL scenarios.

---

# License

MIT — see [LICENSE](LICENSE)
