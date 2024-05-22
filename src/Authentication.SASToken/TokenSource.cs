using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
#nullable enable

namespace Authentication.SASToken
{
    /// <summary>
    /// Class that Validates and Creates SASTokens
    /// </summary>
	public struct TokenSource
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

        static TokenSource()
		{
            Signatures.Add(VERSION_ABSOLUTE_URI, (uri, exp, _) => $"{uri.AbsoluteUri}");
            Signatures.Add(VERSION_HOST, (uri, exp, _) => $"{uri.Host}");
            Signatures.Add(VERSION_RELATIVE_URI, (uri, exp, _) => $"{(uri.IsAbsoluteUri? uri.AbsolutePath:uri.OriginalString)}");
        }


        /// <summary>
        /// This is the public id that is used to match client validation with server secret.
        /// </summary>
        public Guid Id { get; set; }

		/// <summary>
		/// A general name for this token
		/// </summary>
		public string Name { get; set; }

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
			return $"{Id}: {Name??""} - {Version} - {Uri} secret: {Secret?.Length??0}b";
		}

        /// <summary>
        /// Full equality match of all propertys
        /// </summary>
        /// <param name="obj">token source to compare</param>
        /// <returns>True if all properties match</returns>
		public bool Equals(TokenSource obj)
		{
			return 
				Id == obj.Id &&
				Name == obj.Name &&
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
			if (obj is TokenSource) return Equals((TokenSource)obj);
			if (obj is Guid) return Id.Equals((Guid)obj);
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
        /// <param name="endpoint">If null, will use TokenSource.Uri</param>
        /// <param name="expiration">Absolute expiration of token. If null, will use default Expiration + UtcNow</param>
        /// <param name="resource">Additional information that maybe included in signature</param>
        /// <returns>SASToken</returns>
        public SASToken ToToken(Uri? endpoint = null, DateTimeOffset? expiration = null, string? resource = null)
		{
            var signature = Signature ?? GetSignature(Version);
            if (signature is null) throw new KeyNotFoundException($"signature version not found: {Version}");

			System.Security.Cryptography.HMACSHA256 tokenizer = new System.Security.Cryptography.HMACSHA256(Convert.FromBase64String(Secret));
			DateTimeOffset expires = expiration ?? Expiration.ToMax();
            return new SASToken(
				Id, 
				endpoint?.OriginalString??Uri.OriginalString, 
				Convert.ToBase64String(tokenizer.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signature(endpoint ?? Uri, expires, resource)))),
				Version,
				expires);
		}


        /// <summary>
        /// Generates a new SASToken 
        /// </summary>
        /// <param name="expiration">Absolute expiration of token.</param>
        /// <param name="endpoint">If null, will use TokenSource.Uri</param>
        /// <param name="resource">Additional information that maybe included in signature</param>
        /// <returns>SASToken</returns>
        public SASToken ToToken(DateTime expiration, Uri? endpoint = null, string? resource = null) => ToToken(endpoint, new DateTimeOffset(expiration.ToUniversalTime(), TimeSpan.Zero), resource);


        /// <summary>
        /// Validated the given sas token to this token source to verify that this source generated the token and that the token is still valid.
        /// </summary>
        /// <param name="token">Token that was received from a request</param>
        /// <param name="host">(optional: request host name)</param>
        /// <param name="endpoint">(optional: request path</param>
        /// <returns>>true if the signatures match and not expired</returns>
        public bool Validate(SASToken token, Microsoft.AspNetCore.Http.HttpRequest request, Microsoft.Extensions.Logging.ILogger? logger = null)
		{
			return Validate(token, new Uri($"{request.Scheme}://{request.Host.Value}{request.Path}"), logger);
		}

		/// <summary>
		/// Validated the given sas token to this token source to verify that this source generated the token and that the token is still valid.
		/// </summary>
		/// <param name="token">Token that was received from a request</param>
		/// <param name="endpoint">optional: request path</param>
		/// <returns>true if the signatures match and not expired</returns>
		public bool Validate(SASToken token, Uri? endpoint = null, Microsoft.Extensions.Logging.ILogger? logger = null)
		{
			if (Id == Guid.Empty)
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: token source not found", token);
				return false;
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
			if (endpoint != null && Uri.IsAbsoluteUri && !string.IsNullOrEmpty(Uri.Scheme) && !Uri.Scheme.Equals(endpoint.Scheme, StringComparison.OrdinalIgnoreCase))
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: scheme mismatch: source: {1} != {2}", token, Uri.Scheme, endpoint.Scheme);
				return false;
			}
			if (endpoint != null && Uri.IsAbsoluteUri && !string.IsNullOrWhiteSpace(Uri.Host) && Uri.Host != "*" && !Uri.Host.Equals(endpoint.Host, StringComparison.OrdinalIgnoreCase))
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: host mismatch: source: {1} != {2}", token, Uri.Host, endpoint.Host);
				return false;
			}
			if (endpoint != null && Uri.IsAbsoluteUri && !Uri.IsDefaultPort && !Uri.Port.Equals(endpoint.Port))
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: port mismatch: source: {1} != {2}", token, Uri.Port, endpoint.Port);
				return false;
			}
			if (endpoint != null && ((!Uri.IsAbsoluteUri && !string.IsNullOrWhiteSpace(Uri.OriginalString)) || (Uri.IsAbsoluteUri && !string.IsNullOrWhiteSpace(Uri.AbsolutePath) && Uri.AbsolutePath != "/**")))
			{
				// we are going to match the endpoint, given our Uri is in the format of something like /**/name/*startsWith/endsWith*/*contains*/*
				string[] sourceSegments = (!Uri.IsAbsoluteUri?Uri.OriginalString:Uri.AbsolutePath).Split('/');
				string[] targetSegments = endpoint.AbsolutePath.Split('/');
				bool valid = true;
				int ti = 0;
				int tstop = 0;
                int maxDepth = 0;
                int depthOffset = 0;
                int depth = 0;

                for (; depth < sourceSegments.Length && valid && ti < targetSegments.Length; depth++)
				{
					string ss = sourceSegments[depth];
					if (ss == "**")
					{
                        if (string.IsNullOrEmpty(targetSegments[ti])) valid = false;
                        else if (depth == sourceSegments.Length - 1)
                        {
                            ti = targetSegments.Length; // at the end - we will be a match.
                            maxDepth = -1;
                        }
						tstop = -1;
					}
					else if (ss == "*")
					{
                        if (string.IsNullOrEmpty(targetSegments[ti])) valid = false;
                        else if (depth == sourceSegments.Length - 1)
                        {
                            valid = tstop < 0 || ti == targetSegments.Length - 1; // at the end - we will be a match.
                        }
                        else ti++;
                        maxDepth = depth + 1;
                    }
                    else if (ss.StartsWith("*"))
					{
						valid = false;
						if (ss.EndsWith("*"))
						{
                            while ((ss = ss.Substring(1)).StartsWith("*")) ;
                            while ((ss = ss.Substring(0, ss.Length - 1)).EndsWith("*"));
                            for (int k = ti; !valid && ti < targetSegments.Length && (tstop < 0 || ti <= k + tstop); ti++)
                            {
                                valid = targetSegments[ti].IndexOf(ss, StringComparison.OrdinalIgnoreCase) >= 0;
                                if (!valid && tstop < 0 && ti != k) depthOffset++;
                            }
                        }
						else
						{
                            while ((ss = ss.Substring(1)).StartsWith("*")) ;
                            for (int k = ti; !valid && ti < targetSegments.Length && (tstop < 0 || ti <= k + tstop); ti++)
                            {
                                valid = targetSegments[ti].EndsWith(ss, StringComparison.OrdinalIgnoreCase);
                                if (!valid && tstop < 0 && ti != k) depthOffset++;
                            }
						}
					}
					else if (ss.EndsWith("*"))
					{
						valid = false;
                        while ((ss = ss.Substring(0, ss.Length - 1)).EndsWith("*")) maxDepth = -1;
                        for (int k = ti; !valid && ti < targetSegments.Length && (tstop < 0 || ti <= k + tstop); ti++)
                        {
                            valid = targetSegments[ti].StartsWith(ss, StringComparison.OrdinalIgnoreCase);
                            if (!valid && tstop < 0 && ti != k) depthOffset++;
                        }
                    }
					else
					{
                        maxDepth = 0;
						valid = false;
                        for (int k = ti; !valid && ti < targetSegments.Length && (tstop < 0 || ti <= k + tstop); ti++)
                        {
                            valid = targetSegments[ti].Equals(sourceSegments[depth], StringComparison.OrdinalIgnoreCase);
                            if (!valid && tstop < 0 && ti != k) depthOffset++;
                        }
                    }
				}

                if (valid && ((maxDepth == 0 && targetSegments.Length != sourceSegments.Length + depthOffset) || (maxDepth > 0 && targetSegments.Length > maxDepth))) valid = false;

				if (!valid)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: path mismatch: source: {1} != {2}", token, string.Join('/', sourceSegments), string.Join('/', targetSegments));
					return false;
				}
			}

			System.Security.Cryptography.HMACSHA256 tokenizer = new System.Security.Cryptography.HMACSHA256(bSecret);
            var signature = Signature ?? GetSignature(Version);
            if (signature is null) throw new NullReferenceException($"Signature not found for version: {Version}");
            if (token.Signature != Convert.ToBase64String(tokenizer.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signature(this.Uri, token.Expiration, token.Resource)))))
			{
				if (logger != null) logger.LogDebug("Token validation failed {0}: signature mismatch for uri {1} and resource {2}", this.Uri, token, token.Resource);
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
		public static Func<Uri, DateTimeOffset, string?, string>? GetSignature(string version) => Signatures.GetValueOrDefault(version ?? VERSION_ABSOLUTE_URI);
	}
}
