using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using mcdaniel.ws.AspNetCore.Authentication.SASToken.Extensions;
using Microsoft.AspNetCore.Http;
#nullable enable

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
    /// <summary>
    /// Class that Validates and Creates SASTokens
    /// </summary>
	public struct SASTokenKey
	{
        private static readonly DateTimeOffset MaxExpiration = new DateTimeOffset(9999, 12, 31, 0, 0, 0, TimeSpan.Zero);

        /// <summary>
        /// Dictionary of signatures
		/// Takes: Uri, Expiration, roles, resource, ip [range], protocol
		/// Returns: formated signature based on version
        /// </summary>
        public static Dictionary<string, Func<SASTokenKey, SASTokenOptions, string>> Signatures = new Dictionary<string, Func<SASTokenKey, SASTokenOptions, string>>();

		/// <summary>
		/// Embeds token source's full Uri in signature
		/// </summary>
        public const string VERSION_ABSOLUTE_URI = "2024-04";

        /// <summary>
        /// Embeds token source's Host from Uri in signature
        /// </summary>
        public const string VERSION_HOST = "2024-05";

        /// <summary>
        /// Embeds relative path into signature
        /// </summary>
        public const string VERSION_RELATIVE_URI = "2024-06";

        static SASTokenKey()
		{
			// v1 signatures.
			Signatures.Add("2024-01", (key, options) => $"{key.Uri.AbsoluteUri}\r\n{(options.Expiration?? key.Expiration.ToMax()).ToUnixTimeSeconds()}\r\n{string.Join(',',options.Roles??new string[0])}");
			Signatures.Add("2024-02", (key, options) => $"{key.Uri.Host}\r\n{(options.Expiration ?? key.Expiration.ToMax()).ToUnixTimeSeconds()}\r\n{string.Join(',', options.Roles ?? new string[0])}");
			Signatures.Add("2024-03", (key, options) => $"{(key.Uri.IsAbsoluteUri ? key.Uri.AbsolutePath : key.Uri.OriginalString)}\r\n{(options.Expiration ?? key.Expiration.ToMax()).ToUnixTimeSeconds()}\r\n{string.Join(',', options.Roles ?? new string[0])}");

			Func<SASTokenKey, SASTokenOptions, string> defaultProperties = (key, options) => $"\n{(options.Expiration ?? key.Expiration.ToMax()).ToUnixTimeSeconds()}\n{(((options.StartTime??DateTimeOffset.MinValue) == DateTimeOffset.MinValue) ? "" : options.StartTime!.Value.ToUnixTimeSeconds())}\n{string.Join(',', options.Roles ?? new string[0])}\n{options.Resource ?? key.Resource ?? ""}\n{key.AllowedIPAddresses??""}\n{key.Protocol ?? ""}";
			// v2 signatures
			Signatures.Add(VERSION_ABSOLUTE_URI, (key, options) => key.Uri.AbsoluteUri+defaultProperties(key,options));
			Signatures.Add(VERSION_HOST, (key, options) => key.Uri.Host + defaultProperties(key, options));
			Signatures.Add(VERSION_RELATIVE_URI, (key, options) => (key.Uri.IsAbsoluteUri ? key.Uri.AbsolutePath : key.Uri.OriginalString) + defaultProperties(key, options));
		}

		/// <summary>
		/// Constructor
		/// </summary>
		public SASTokenKey()
        {
            Id = string.Empty;
            Description = string.Empty;
            Version = string.Empty;
            Uri = new Uri("/", UriKind.Relative);
            Secret = string.Empty;
            Signature = null;
            Expiration = TimeSpan.MaxValue;
        }

		/// <summary>
		/// Copy Constructor
		/// </summary>
		/// <param name="copy">Key to copy</param>
        public SASTokenKey(SASTokenKey copy)
        {
            Id = copy.Id;
            Description = copy.Description;
            Secret = copy.Secret;
            Uri = copy.Uri;
            Version = copy.Version;
            Signature = copy.Signature;
            Expiration = copy.Expiration;
			ValidateVersion = copy.ValidateVersion;
        }

        /// <summary>
        /// This is the public id that is used to match client validation with server secret.
        /// </summary>
        public string Id { get; set; }

		/// <summary>
		/// A description of what the this token is used for
		/// </summary>
		public string Description { get; set; }

		/// <summary>
		/// This is the secret that will generate signatures
		/// </summary>
		public string Secret { get; set; }

		/// <summary>
		/// This is a uri used to validate requests.
		/// </summary>
		/// <remarks>
		/// This supports relative or absolute paths with wildcard support
		///   ** says any path, * says any segment
		///   *PATH: startswith
		///   PATH*: ends with
		///   *PATH*: contains
		/// </remarks>
		/// <example>
		/// https://hostname/**/api/version_*/controller/endpoint
		/// </example>
		public Uri Uri { get; set; }

		/// <summary>
		/// The version is used to specify the version of the signature generation
		/// </summary>
		public string Version { get; set; }

		/// <summary>
		/// The resource that this SASToken protects
		/// </summary>
		public string? Resource { get; set; }

		/// <summary>
		/// a string specifies 1 or more IPAddresses in the formats: (x.x.x.x can be ipv4 or ipv6)
		/// x.x.x.x - single IP Address
		/// x.x.x.x/CIDR - IPAddress with CIDR Range
		/// x.x.x.x-x.x.x.x - IPAddress range
		/// </summary>
		public string? AllowedIPAddresses { get; set; }

		/// <summary>
		/// default protocol this key is applied to.  ex. http,https
		/// </summary>
		public string? Protocol { get; set; }

		/// <summary>
		/// Function to generate the signature. If null, uses default in the format of Uri\nUnixTimeInSeconds
		/// </summary>
		/// <remarks>
		/// Signatures should always include the expiration for validation!
		/// </remarks>
		public Func<SASTokenKey, SASTokenOptions, string>? Signature { get; set; }

		/// <summary>
		/// This is the default Expiration used to generate new tokens
		/// </summary>
		[System.Text.Json.Serialization.JsonConverter(typeof(JsonConverters.TimeSpanConverter))]
		public TimeSpan Expiration { get; set; } = TimeSpan.MaxValue;

		/// <summary>
		/// Forces validation to verify the token has the same version
		/// </summary>
		/// <remarks>
		/// When updating a version for a SASTokenKey, you may set this to false to let existing SASToken validation succeed.
		/// </remarks>
		public bool ValidateVersion { get; set; } = true;

        /// <summary>
        /// Overridden.
        /// </summary>
        /// <returns>Information about source</returns>
		public override string ToString()
		{
			return $"{Id}: {Description??""} - {Version} - {Uri} secret: {Secret?.Length??0}b";
		}

        /// <summary>
        /// Full equality match of all propertys
        /// </summary>
        /// <param name="obj">token source to compare</param>
        /// <returns>True if all properties match</returns>
		public bool Equals(SASTokenKey obj)
		{
			return 
				Id == obj.Id &&
				Description == obj.Description &&
				Secret == obj.Secret &&
				Uri == obj.Uri &&
				Version == obj.Version &&
				Resource == obj.Resource &&
				AllowedIPAddresses == obj.AllowedIPAddresses &&
				Protocol == obj.Protocol &&
				Expiration == obj.Expiration &&
				ValidateVersion == obj.ValidateVersion;
		}

        /// <summary>
        /// Overriden. 
        /// </summary>
        /// <param name="obj"></param>
        /// <returns>True if all properties match or obj is Guid and matches Id</returns>
		public override bool Equals(object? obj)
		{
            if (obj is null) return false;
			if (obj is SASTokenKey) return Equals((SASTokenKey)obj);
			if (obj is string) return Id.Equals((string)obj);
			return base.Equals(obj);
		}

        /// <summary>
        /// overridden
        /// </summary>
        /// <returns>hash code of Id</returns>
		public override int GetHashCode()
		{
			return Id.GetHashCode();
		}

		/// <summary>
		/// Generates a SASToken given options
		/// </summary>
		/// <param name="options">The options used to create the SASToken</param>
		/// <returns>SASToken</returns>
		/// <exception cref="KeyNotFoundException">thrown if signature not found for version</exception>
		public SASToken ToToken(SASTokenOptions options)
		{
			var signature = Signature ?? GetSignature(Version);
			if (signature is null) throw new KeyNotFoundException($"signature version not found: {Version}");

			System.Security.Cryptography.HMACSHA256 tokenizer = new System.Security.Cryptography.HMACSHA256(Convert.FromBase64String(Secret));
			DateTimeOffset expires = options.Expiration ?? Expiration.ToMax();
			string roleString = options.Roles==null?"":string.Join(',', options.Roles.Where(r => !string.IsNullOrWhiteSpace(r)));

			return new SASToken(
				Id,
				roleString,
				options.Resource??Resource,
				options.AllowedIPAddresses??AllowedIPAddresses,
				options.Protocol??Protocol,
				Convert.ToBase64String(tokenizer.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signature(this, options)))),
				Version,
				expires,
				options.StartTime??DateTimeOffset.MinValue);
		}

		/// <summary>
		/// Generates a new SASToken 
		/// </summary>
		/// <param name="expiration">Absolute expiration of token. If null, will use default Expiration + UtcNow</param>
		/// <param name="roles">Additional information that maybe included in signature</param>
		/// <returns>SASToken</returns>
		public SASToken ToToken(DateTimeOffset? expiration, params string[] roles) => ToToken(new SASTokenOptions() { Expiration = expiration, Roles = roles });

		/// <summary>
		/// Generates a new SASToken 
		/// </summary>
		/// <param name="roles">Roles that can be used during authentication</param>
		/// <returns>SASToken</returns>
		public SASToken ToToken(params string[] roles) => ToToken(new SASTokenOptions() { Roles = roles });

		/// <summary>
		/// Generates a new SASToken 
		/// </summary>
		/// <param name="expiration">Absolute expiration of token.</param>
		/// <param name="roles">Additional information that maybe included in signature</param>
		/// <returns>SASToken</returns>
		public SASToken ToToken(DateTime expiration, params string[] roles) => ToToken(new SASTokenOptions() { Expiration = new DateTimeOffset(expiration.ToUniversalTime(), TimeSpan.Zero), Roles = roles });


		/// <summary>
		/// Validated the given sas token to this token source to verify that this source generated the token and that the token is still valid.
		/// </summary>
		/// <param name="token">Token that was received from a request</param>
		/// <param name="request">Current HttpRequest</param>
		/// <param name="roles">list of roles to require the sastoken to have any of.  If null, no roles will be required.</param>
		/// <param name="resourceOverride">required resource, if null - uses SASTokenKey.Resource</param>
		/// <param name="clientIP">the client ip address</param>
		/// <param name="logger">a logger to use when validating tokens</param>
		/// <returns>>true if the signatures match and not expired</returns>
		public bool Validate(SASToken token, Microsoft.AspNetCore.Http.HttpRequest request, IEnumerable<string>? roles = null, string? resourceOverride=null, IPAddress? clientIP = null, Microsoft.Extensions.Logging.ILogger? logger = null)
		{
			return Validate(token, new Uri($"{request.Scheme}://{request.Host.Value}{request.Path}"), roles, resourceOverride, clientIP, null, logger);
		}

		/// <summary>
		/// Validated the given sas token to this token source to verify that this source generated the token and that the token is still valid.
		/// </summary>
		/// <param name="token">Token that was received from a request</param>
		/// <param name="endpoint">current request path</param>
		/// <param name="roles">list of roles to require the sastoken to have any of.  If null, no roles will be required.</param>
		/// <param name="resourceOverride">required resource, if null - uses SASTokenKey.Resource</param>
		/// <param name="clientIP">remote client ip</param>
		/// <param name="scheme">allowed protocol schemes: ex. http,https - If null - uses SASTokenKey.Protocol</param>
		/// <param name="logger">a logger to use when validating tokens</param>
		/// <returns>true if the signatures match and not expired</returns>
		public bool Validate(SASToken token, Uri? endpoint, IEnumerable<string>? roles = null, string? resourceOverride = null, IPAddress? clientIP = null, string? scheme = null, Microsoft.Extensions.Logging.ILogger? logger = null)
		{
			if (roles is not null && roles.Count() > 0)
			{
				if (token.Roles?.Length == 0)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: no required roles given. required: {1}", token, string.Join(",", roles));
					return false;
				}
				HashSet<string> givenRoles = new HashSet<string>(token.Roles?.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrEmpty(r))??new string[0]);
				if (givenRoles.Intersect(roles).Count()==0)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: required roles not found: present: {1} required: {2}", token, string.Join(",", givenRoles), string.Join(",", roles));
					return false;
				}
			}

			if (token.StartTime != DateTime.MinValue && token.StartTime >= DateTimeOffset.UtcNow)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: token not valid yet: {1} < {2}", token, token.StartTime, DateTimeOffset.UtcNow);
				return false;
			}

			if (ValidateVersion && Version != token.Version)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: version mismatch {1}", token, Version??"");
				return false;
			}

			if (!string.IsNullOrWhiteSpace(resourceOverride ?? Resource))
			{
				if (string.IsNullOrWhiteSpace(token.Resource))
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: no token resource found. required: {2}", token, resourceOverride ?? Resource);
					return false;
				}
				HashSet<string> reqResources = new HashSet<string>((resourceOverride ?? Resource)!.Split(',').Select(p => p.Trim().ToLowerInvariant()).Where(p => !string.IsNullOrWhiteSpace(p)));
				HashSet<string> forResources = new HashSet<string>(token.Resource.Split(',').Select(p => p.Trim().ToLowerInvariant()).Where(p => !string.IsNullOrWhiteSpace(p)));
				if (forResources.Intersect(reqResources).Count() == 0)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: invalid token resource. present: {1} required: {2}", token, token.Resource, resourceOverride ?? Resource);
					return false;
				}
			}

			if (!string.IsNullOrWhiteSpace(scheme??token.Protocol??Protocol))
			{
				if (!(scheme ?? token.Protocol ?? Protocol!).Split(',').Select(p => p.Trim().ToLowerInvariant()).Where(p => !string.IsNullOrWhiteSpace(p)).Any(p => p.Equals(endpoint?.Scheme?.ToLowerInvariant() ?? "", StringComparison.OrdinalIgnoreCase)))
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: invalid token protocol. present: {1} required: {2}", token, endpoint?.Scheme ?? "", scheme ?? token.Protocol ?? Protocol!);
					return false;
				}
			}

			if (Secret == null || Secret.Length == 0)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: invalid token source secret", token);
				return false;
			}
			try
			{
				if (token.AllowedIPAddresses != null)
				{
					if (!clientIP?.IsInRange(token.AllowedIPAddresses)??false)
					{
						if (logger != null) logger.LogDebug("Token validation failed {0}: IP Address out of token range {1} ~= {2}", token, clientIP?.ToString()??"0.0.0.0", token.AllowedIPAddresses??"");
						return false;
					}
				}
				else if (AllowedIPAddresses != null)
				{
					if (!clientIP?.IsInRange(AllowedIPAddresses) ?? false)
					{
						if (logger != null) logger.LogDebug("Token validation failed {0}: IP Address out of key range {1} ~= {2}", token, clientIP?.ToString() ?? "0.0.0.0", AllowedIPAddresses ?? "");
						return false;
					}
				}
			}
			catch (FormatException ex)
			{
				if (logger != null) logger.LogWarning(ex, "Token validation skipped {0}: Allowed IPAddresses range is not well-formed.", token);
			}

			byte[]? bSecret = null;
			try 
			{ 
				bSecret = Convert.FromBase64String(Secret); 
			}
			catch (Exception)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: invalid token source secret: invalid base64 encoding", token);
				return false;
			}

			if (bSecret == null || bSecret.Length == 0)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: invalid token source secret: invalid length: {1} > 0", token, bSecret?.Length??0);
				return false;
			}

			if (token.IsExpired)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: expired token ({1:o})", token, token.Expiration);
				return false;
			}

			if (!Uri.IsMatch(endpoint, logger))
			{
				return false;
			}

			using (System.Security.Cryptography.HMACSHA256 tokenizer = new System.Security.Cryptography.HMACSHA256(bSecret))
			{
				// if we don't validate the version, we can use the signature from the token instead of the key.
				var signature = (!ValidateVersion ? GetSignature(token.Version) : Signature) ?? GetSignature(Version);
				if (signature is null) throw new NullReferenceException($"Signature not found for version: {Version}");
				SASTokenOptions options = new SASTokenOptions()
				{
					AllowedIPAddresses = token.AllowedIPAddresses,
					Expiration = token.Expiration,
					Protocol = token.Protocol,
					Resource = token.Resource,
					Roles = token.Roles?.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrEmpty(r))??new string[0],
					StartTime = token.StartTime
				};
				if (token.Signature != Convert.ToBase64String(tokenizer.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signature(this, options)))))
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: signature mismatch for uri {1},roles: {2}, resource: {3}, ip range:{4}, scheme:{5}", this.Uri, token, token.Roles, token.Resource ?? Resource ?? "", token.AllowedIPAddresses ?? AllowedIPAddresses ?? "", token.Protocol ?? Protocol ?? "");
					return false;
				}
			}

			if (logger != null)
			{
				logger.LogDebug("Token validation success {0}", token);
			}
			return true;
		}

		/// <summary>
		/// Generates a 32 byte, base 64 encoded Secret.
		/// </summary>
		/// <returns></returns>
		public static string GenerateSecret(byte len = 32)
		{
			RandomNumberGenerator rng = RandomNumberGenerator.Create();
			byte[] data = new byte[len];
			rng.GetBytes(data);
			return Convert.ToBase64String(data);
		}

        /// <summary>
        /// Gets a predefined signature generation function
        /// </summary>
        /// <param name="version">The version for the generator</param>
        /// <returns>Function that generates a signature from uri, absolute expiration and possible additional data.</returns>
		public static Func<SASTokenKey, SASTokenOptions, string>? GetSignature(string? version) => Signatures.GetValueOrDefault(version ?? VERSION_ABSOLUTE_URI);
	}
}
