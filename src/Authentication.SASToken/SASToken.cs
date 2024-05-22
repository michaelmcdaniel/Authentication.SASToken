﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace Authentication.SASToken
{
    /// <summary>
    /// A token that is used to authenticate to an endpoint
    /// </summary>
	public struct SASToken
	{
		/// <summary>
		/// An empty token
		/// </summary>
		public static readonly SASToken Empty = new SASToken();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">Id of the TokenSource</param>
        /// <param name="resource">Requested resource</param>
        /// <param name="signature">Authentication Signature</param>
        /// <param name="version">Version of the function that generates signatures</param>
        /// <param name="expiration">Absolute expiration of the SASToken (seconds since epoch)</param>
		public SASToken(Guid id, string resource, string signature, string version, long expiration)
		{
			Id = id;
			Resource = resource;
			Signature = signature;
			Version = version;
            Expiration = DateTimeOffset.FromUnixTimeSeconds(expiration);
		}

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="id">Id of the TokenSource</param>
        /// <param name="resource">Requested resource</param>
        /// <param name="signature">Authentication Signature</param>
        /// <param name="version">Version of the function that generates signatures</param>
        /// <param name="expiration">Absolute expiration of the SASToken</param>
		public SASToken(Guid id, string resource, string signature, string version, DateTimeOffset expiration)
		{
			Id = id;
			Resource = resource;
			Signature = signature;
			Version = version;
			Expiration = expiration;
		}

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="queryString">http query string of parameters</param>
		public SASToken(Microsoft.AspNetCore.Http.QueryString queryString)
		{
			var qs = QueryHelpers.ParseQuery(queryString.Value);
			Guid id;
			long expiration;
			Microsoft.Extensions.Primitives.StringValues version, signature, se, skn, resource;
			if (qs.TryGetValue("v", out version)) { Version = version; } 
            else if (qs.TryGetValue("api-version", out version)) { Version = version; }
            else { Version = Empty.Version; }
			if (qs.TryGetValue("sig", out signature)) { Signature = signature; } else { Signature = Empty.Signature; }
			if (qs.TryGetValue("se", out se) && long.TryParse(se, out expiration)) { Expiration = DateTimeOffset.FromUnixTimeSeconds(expiration); } else { Expiration = Empty.Expiration; }
			if (qs.TryGetValue("skn", out skn) && Guid.TryParse(skn.ToString(), out id)) { Id = id; } else { Id = Empty.Id; }
			if (qs.TryGetValue("sr", out resource)) { Resource = resource; } else { Resource = Empty.Resource; }
		}

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="endpoint">endpoint of the http request</param>
        /// <param name="queryString">http query string of parameters</param>
		public SASToken(Uri endpoint, Microsoft.AspNetCore.Http.QueryString queryString)
		{
			var qs = QueryHelpers.ParseQuery(queryString.Value);
			Guid id;
			long expiration;
			
			Microsoft.Extensions.Primitives.StringValues version, signature, se, skn, resource;
            if (qs.TryGetValue("v", out version)) { Version = version; }
            else if (qs.TryGetValue("api-version", out version)) { Version = version; }
            else { Version = Empty.Version; }
            if (qs.TryGetValue("sig", out signature)) { Signature = signature; } else { Signature = Empty.Signature; }
			if (qs.TryGetValue("se", out se) && long.TryParse(se, out expiration)) { Expiration = DateTimeOffset.FromUnixTimeSeconds(expiration); } else { Expiration = Empty.Expiration; }
			if (qs.TryGetValue("skn", out skn) && Guid.TryParse(skn.ToString(), out id)) { Id = id; } else { Id = Empty.Id; }
			if (qs.TryGetValue("sr", out resource)) { Resource = resource; } else { Resource = Empty.Resource; }
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="copy"></param>
		public SASToken(SASToken? copy)
		{
            if (copy is not null)
            {
                Id = copy.Value.Id;
                Resource = copy.Value.Resource;
                Signature = copy.Value.Signature;
                Version = copy.Value.Version;
                Expiration = copy.Value.Expiration;
            }
		}

		/// <summary>
		/// The Id of the SASToken
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("skn")]
		public Guid Id { get; set; }

		/// <summary>
		/// The storage resource used for endpoint validation
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("sr")]
		public string Resource { get; set; }

		/// <summary>
		/// This is hashed data from the token source to validate a request.
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("sig")]
		public string Signature { get; set; }

		/// <summary>
		/// This is the version of the signature data
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("api-version")]
		public string Version { get; set; }

		/// <summary>
		/// This is when the sas token expires
		/// </summary>
		[System.Text.Json.Serialization.JsonConverter(typeof(JsonConverters.UnixSecondsConverter))]
		public DateTimeOffset Expiration { get; set; }

		/// <summary>
		/// Overridden. returns SAStoken in query string form.
		/// </summary>
		/// <returns>query string</returns>
		public override string ToString()
		{
			return string.Format("api-version={0}&sr={1}&sig={2}&se={3}&skn={4}", Version, System.Net.WebUtility.UrlEncode(Resource??""), System.Net.WebUtility.UrlEncode(Signature), Expiration.ToUnixTimeSeconds(), System.Net.WebUtility.UrlEncode(Id.ToString()));
		}

		/// <summary>
		/// returns SAStoken in header format.
		/// </summary>
		/// <returns>KeyValuePair where the key is the header type and the value is the value for the header</returns>
		public KeyValuePair<string,string> ToHttpResponseHeader()
		{
			return new KeyValuePair<string, string>("Authorization", string.Format("SharedAccessSignature api-version={0}&sr={1}&sig={2}&se={3}&skn={4}", Version, System.Net.WebUtility.UrlEncode(Resource??""), System.Net.WebUtility.UrlEncode(Signature), Expiration.ToUnixTimeSeconds(), System.Net.WebUtility.UrlEncode(Id.ToString())));
		}

		/// <summary>
		/// True if the token is expired.
		/// </summary>
		[System.Text.Json.Serialization.JsonIgnore]
		public bool IsExpired { get => Expiration < DateTimeOffset.UtcNow; }

		/// <summary>
		/// True if the token is empty.
		/// </summary>
		[System.Text.Json.Serialization.JsonIgnore]
		public bool IsEmpty { get => Equals(Empty); }

        /// <summary>
        /// Overriden. 
        /// </summary>
        /// <param name="token">The SASToken to compare</param>
        /// <returns>True if all properties match</returns>
		public bool Equals(SASToken token)
		{
            var expLHS = new DateTime(Expiration.Year, Expiration.Month, Expiration.Day, Expiration.Hour, Expiration.Minute, Expiration.Second);
            var expRHS = new DateTime(token.Expiration.Year, token.Expiration.Month, token.Expiration.Day, token.Expiration.Hour, token.Expiration.Minute, token.Expiration.Second);
            return
                            Id == token.Id &&
				(Resource?.Equals(token.Resource, StringComparison.OrdinalIgnoreCase)??false) &&
				Signature == token.Signature &&
				Version == token.Version &&
                expLHS == expRHS;
		}

        /// <summary>
        /// checks equality against types: SASToken, TokenSource.Validate(this), Guid==(Id)
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
		public override bool Equals(object obj)
		{
			if (obj is SASToken) return Equals((SASToken)obj);
			if (obj is TokenSource) return ((TokenSource)obj).Validate(this);
			if (obj is Guid) return Id == (Guid)obj;
			return base.Equals(obj);
		}

        /// <summary>
        /// Overridden.
        /// </summary>
        /// <returns>Hashcode of Id</returns>
		public override int GetHashCode()
		{
			return Id.GetHashCode();
		}

        /// <summary>
        /// Tries to parse SASToken from either Authorization header format or QueryString format.
        /// </summary>
        /// <param name="value">the value to parse</param>
        /// <param name="token">return token</param>
        /// <returns>true if all field found.</returns>
		public static bool TryParse(string value, out SASToken token)
		{
			if (value.StartsWith("SharedAccessSignature ")) value = value.Substring("SharedAccessSignature ".Length);
			//api-version={0}&sr={1}&sig={2}&se={3}&skn={4}
			var qs = QueryHelpers.ParseQuery(value);
			Microsoft.Extensions.Primitives.StringValues version, signature, se, skn, resource;
			if (!(qs.TryGetValue("api-version", out version) || qs.TryGetValue("version", out version) || qs.TryGetValue("v", out version))) { token = Empty; return false; }
			if (!qs.TryGetValue("sig", out signature)) { token = Empty; return false; }
			if (!qs.TryGetValue("se", out se)) { token = Empty; return false; }
			if (!qs.TryGetValue("skn", out skn)) { token = Empty; return false; }
			if (!qs.TryGetValue("sr", out resource)) { token = Empty; return false; }
			Guid id;
			if (!Guid.TryParse(skn.ToString(), out id) || id == Guid.Empty) { token = Empty; return false; }
			long expiration;
			if (!long.TryParse(se, out expiration)) { token = Empty; return false; }
			token = new SASToken(id, resource, signature, version, expiration);
			return true;
		}

        /// <summary>
        /// Tries to parse SASToken from either Authorization header format or QueryString format.
        /// Overrides Resource with given uri
        /// </summary>
        /// <param name="value">the value to parse</param>
        /// <param name="endpoint">override resource with endpoint</param>
        /// <param name="token">return token</param>
        /// <returns>true if all field found</returns>
		public static bool TryParse(string value, Uri endpoint, out SASToken token)
		{
			if (value.StartsWith("SharedAccessSignature ")) value = value.Substring("SharedAccessSignature ".Length);
			//api-version={0}&sr={1}&sig={2}&se={3}&skn={4}
			var qs = QueryHelpers.ParseQuery(value);
			Microsoft.Extensions.Primitives.StringValues version, signature, se, skn, resource;
			if (!(qs.TryGetValue("api-version", out version) || qs.TryGetValue("version", out version) || qs.TryGetValue("v", out version))) { token = Empty; return false; }
			if (!qs.TryGetValue("sig", out signature)) { token = Empty; return false; }
			if (!qs.TryGetValue("se", out se)) { token = Empty; return false; }
			if (!qs.TryGetValue("skn", out skn)) { token = Empty; return false; }
			if (!qs.TryGetValue("sr", out resource))
			{ 
				resource = endpoint.OriginalString;
				if (string.IsNullOrEmpty(resource)) { token = Empty; return false; } 
			}
			Guid id;
			if (!Guid.TryParse(skn.ToString(), out id) || id == Guid.Empty) { token = Empty; return false; }
			long expiration;
			if (!long.TryParse(se, out expiration)) { token = Empty; return false; }
			token = new SASToken(id, resource, signature, version, expiration);
			return true;
		}

	}
}
