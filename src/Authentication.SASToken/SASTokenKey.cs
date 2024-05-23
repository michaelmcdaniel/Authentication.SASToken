using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
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
        /// </summary>
        public static Dictionary<string, Func<Uri, DateTimeOffset, string?, string>> Signatures = new Dictionary<string, Func<Uri, DateTimeOffset, string?, string>>();

        /// <summary>
        /// Embeds token source's full Uri in signature
        /// </summary>
        public const string VERSION_ABSOLUTE_URI = "2024-01";

        /// <summary>
        /// Embeds token source's Host from Uri in signature
        /// </summary>
        public const string VERSION_HOST = "2024-02";

        /// <summary>
        /// Embeds relative path into signature
        /// </summary>
        public const string VERSION_RELATIVE_URI = "2024-03";

        static SASTokenKey()
		{
            Signatures.Add(VERSION_ABSOLUTE_URI, (uri, exp, r) => $"{uri.AbsoluteUri}\r\n{exp.ToUnixTimeSeconds()}\r\n{r ?? ""}");
            Signatures.Add(VERSION_HOST, (uri, exp, r) => $"{uri.Host}\r\n{exp.ToUnixTimeSeconds()}\r\n{r ?? ""}");
            Signatures.Add(VERSION_RELATIVE_URI, (uri, exp, r) => $"{(uri.IsAbsoluteUri? uri.AbsolutePath:uri.OriginalString)}\r\n{exp.ToUnixTimeSeconds()}\r\n{r ?? ""}");
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
		/// Function to generate the signature. If null, uses default in the format of Uri\nUnixTimeInSeconds
		/// </summary>
		/// <remarks>
		/// Signatures should always include the expiration for validation!
		/// </remarks>
		public Func<Uri, DateTimeOffset, string?, string>? Signature { get; set; }

		/// <summary>
		/// This is the default Expiration used to generate new tokens
		/// </summary>
		[System.Text.Json.Serialization.JsonConverter(typeof(JsonConverters.TimeSpanConverter))]
		public TimeSpan? Expiration { get; set; }

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
				Expiration == obj.Expiration;
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
        /// Generates a new SASToken 
        /// </summary>
        /// <param name="expiration">Absolute expiration of token. If null, will use default Expiration + UtcNow</param>
        /// <param name="roles">Additional information that maybe included in signature</param>
        /// <returns>SASToken</returns>
        public SASToken ToToken(DateTimeOffset? expiration, params string[] roles)
		{
            var signature = Signature ?? GetSignature(Version);
            if (signature is null) throw new KeyNotFoundException($"signature version not found: {Version}");

			System.Security.Cryptography.HMACSHA256 tokenizer = new System.Security.Cryptography.HMACSHA256(Convert.FromBase64String(Secret));
			DateTimeOffset expires = expiration ?? Expiration.ToMax();
			string roleString = string.Join(',', roles.Where(r=>!string.IsNullOrWhiteSpace(r)));

			return new SASToken(
				Id,
				roleString, 
				Convert.ToBase64String(tokenizer.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signature(Uri, expires, roleString)))),
				Version,
				expires);
		}

		/// <summary>
		/// Generates a new SASToken 
		/// </summary>
		/// <param name="roles">Roles that can be used during authentication</param>
		/// <returns>SASToken</returns>
		public SASToken ToToken(params string[] roles) => ToToken((DateTimeOffset?)null, roles);

		/// <summary>
		/// Generates a new SASToken 
		/// </summary>
		/// <param name="expiration">Absolute expiration of token.</param>
		/// <param name="roles">Additional information that maybe included in signature</param>
		/// <returns>SASToken</returns>
		public SASToken ToToken(DateTime expiration, params string[] roles) => ToToken(new DateTimeOffset(expiration.ToUniversalTime(), TimeSpan.Zero), roles);


		/// <summary>
		/// Validated the given sas token to this token source to verify that this source generated the token and that the token is still valid.
		/// </summary>
		/// <param name="token">Token that was received from a request</param>
		/// <param name="request">Current HttpRequest</param>
		/// <param name="roles">list of roles to require the sastoken to have any of.  If null, no roles will be required.</param>
		/// <param name="logger">a logger to use when validating tokens</param>
		/// <returns>>true if the signatures match and not expired</returns>
		public bool Validate(SASToken token, Microsoft.AspNetCore.Http.HttpRequest request, IEnumerable<string>? roles = null, Microsoft.Extensions.Logging.ILogger? logger = null)
		{
			return Validate(token, new Uri($"{request.Scheme}://{request.Host.Value}{request.Path}"), roles, logger);
		}

		/// <summary>
		/// Validated the given sas token to this token source to verify that this source generated the token and that the token is still valid.
		/// </summary>
		/// <param name="token">Token that was received from a request</param>
		/// <param name="endpoint">current request path</param>
		/// <param name="roles">list of roles to require the sastoken to have any of.  If null, no roles will be required.</param>
		/// <param name="logger">a logger to use when validating tokens</param>
		/// <returns>true if the signatures match and not expired</returns>
		public bool Validate(SASToken token, Uri endpoint, IEnumerable<string>? roles = null, Microsoft.Extensions.Logging.ILogger? logger = null)
		{
			if (roles is not null && roles.Count() > 0)
			{
				if (token.Roles?.Length == 0)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: no required roles given. required: {1}", token, string.Join(",", roles));
					return false;
				}
				HashSet<string> givenRoles = new HashSet<string>(token.Roles!.Split(',').Select(r=>r.Trim()).Where(r=>!string.IsNullOrEmpty(r)));
				if (givenRoles.Intersect(roles).Count()==0)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: required roles not found: present: {1} required: {2}", token, string.Join(",", givenRoles), string.Join(",", roles));
					return false;
				}
			}
			if (Version != token.Version)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: version mismatch {1}", token, Version??"");
				return false;
			}
			if (Secret == null || Secret.Length == 0)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: invalid token source secret", token);
				return false;
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

			System.Security.Cryptography.HMACSHA256 tokenizer = new System.Security.Cryptography.HMACSHA256(bSecret);
            var signature = Signature ?? GetSignature(Version);
            if (signature is null) throw new NullReferenceException($"Signature not found for version: {Version}");
            if (token.Signature != Convert.ToBase64String(tokenizer.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signature(this.Uri, token.Expiration, token.Roles)))))
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: signature mismatch for uri {1} and resource {2}", this.Uri, token, token.Roles);
				return false;
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
		public static Func<Uri, DateTimeOffset, string?, string>? GetSignature(string? version) => Signatures.GetValueOrDefault(version ?? VERSION_ABSOLUTE_URI);
	}
}
