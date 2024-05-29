using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using System.Net;
#nullable enable

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
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
		/// <param name="id">Id of the SASTokenKey</param>
		/// <param name="roles">Requested roles</param>
		/// <param name="allowedIPAddresses">Allowed ipaddress(es)</param>
		/// <param name="protocol">Allowed Protocols like http,https</param>
		/// <param name="resource">The resource</param>
		/// <param name="signature">Authentication Signature</param>
		/// <param name="version">Version of the function that generates signatures</param>
		/// <param name="expiration">Absolute expiration of the SASToken (seconds since epoch)</param>
		/// <param name="startTime">Absolute start of the SASToken (seconds since epoch)</param>
		public SASToken(string? id, string? roles, string? resource, string? allowedIPAddresses, string? protocol, string? signature, string? version, long expiration, long startTime)
		{
			Id = id;
			Roles = roles;
			Resource = resource;
			Signature = signature;
			Version = version;
            Expiration = DateTimeOffset.FromUnixTimeSeconds(expiration);
			AllowedIPAddresses = allowedIPAddresses;
			Protocol = protocol;
			if (startTime <= 0) StartTime = DateTimeOffset.MinValue;
			else StartTime = DateTimeOffset.FromUnixTimeSeconds(startTime);
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="id">Id of the SASTokenKey</param>
		/// <param name="resource">The resource</param>
		/// <param name="roles">Requested roles</param>
		/// <param name="allowedIPAddresses">Allowed ipaddress(es)</param>
		/// <param name="protocol">Allowed Protocols like http,https</param>
		/// <param name="signature">Authentication Signature</param>
		/// <param name="version">Version of the function that generates signatures</param>
		/// <param name="expiration">Absolute expiration of the SASToken</param>
		/// <param name="startTime">Absolute start of the SASToken (seconds since epoch)</param>
		public SASToken(string? id, string? roles, string? resource, string? allowedIPAddresses, string? protocol, string? signature, string? version, DateTimeOffset expiration, DateTimeOffset startTime)
		{
			Id = id;
			Roles = roles;
			Resource = resource;
			Signature = signature;
			Version = version;
			Expiration = expiration;
			AllowedIPAddresses = allowedIPAddresses;
			Protocol = protocol;
			StartTime = startTime;
		}

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="queryString">http query string of parameters</param>
		public SASToken(Microsoft.AspNetCore.Http.QueryString queryString)
		{
			var qs = QueryHelpers.ParseQuery(queryString.Value);
			long expiration;
			long startTime;
			Microsoft.Extensions.Primitives.StringValues version, signature, se, st, skn, roles, resource, allowedIPs, allowedProtocols;
			if (qs.TryGetValue("sv", out version)) { Version = version!; }
			else if(qs.TryGetValue("v", out version)) { Version = version!; }
			else if (qs.TryGetValue("api-version", out version)) { Version = version!; }
            else { Version = Empty.Version; }
			if (qs.TryGetValue("sig", out signature)) { Signature = signature!; } else { Signature = Empty.Signature; }
			if (qs.TryGetValue("se", out se) && long.TryParse(se, out expiration)) { Expiration = DateTimeOffset.FromUnixTimeSeconds(expiration); } else { Expiration = Empty.Expiration; }
			if (qs.TryGetValue("st", out st) && long.TryParse(st, out startTime)) { StartTime = startTime==0?DateTimeOffset.MinValue:DateTimeOffset.FromUnixTimeSeconds(startTime); } else { StartTime = DateTimeOffset.MinValue; }
			if (qs.TryGetValue("skn", out skn)) { Id = skn!; } else { Id = Empty.Id; }
			if (qs.TryGetValue("sp", out roles)) { Roles = roles!; } else { Roles = Empty.Roles; }
			if (qs.TryGetValue("sr", out resource)) { Resource = resource!; } else { Resource = string.Empty; }
			if (qs.TryGetValue("sip", out allowedIPs)) { AllowedIPAddresses = allowedIPs; } else { AllowedIPAddresses = string.Empty; }
			if (qs.TryGetValue("spr", out allowedProtocols)) { Protocol = allowedProtocols; } else { Protocol = string.Empty; }
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
                Roles = copy.Value.Roles;
                Signature = copy.Value.Signature;
                Version = copy.Value.Version;
                Expiration = copy.Value.Expiration;
				Resource = copy.Value.Resource;
				AllowedIPAddresses = copy.Value.AllowedIPAddresses;
				StartTime = copy.Value.StartTime;
				Protocol = copy.Value.Protocol;
            }
			else
			{ 
				Id = Empty.Id;
				Roles = Empty.Roles;
				Signature = Empty.Signature;
				Version = Empty.Version;
				Expiration = Empty.Expiration;
				Resource = Empty.Resource;
				AllowedIPAddresses = Empty.AllowedIPAddresses;
				Protocol = Empty.Protocol;
			}
		}

		/// <summary>
		/// The Id of the SASToken
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("skn")]
		public string? Id { get; set; }

		/// <summary>
		/// Comma separated list of roles that can be used for endpoint validation
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("sp")]
		public string? Roles { get; set; }


		/// <summary>
		/// Resource that can be applied used for endpoint validation
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("sr")]
		public string? Resource { get; set; }

		/// <summary>
		/// This is hashed data from the token source to validate a request.
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("sig")]
		public string? Signature { get; set; }

		/// <summary>
		/// This is the version of the signature data
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("sv")]
		public string? Version { get; set; }


		/// <summary>
		/// Optional start time for the SASToken to be valid. By default, MinValue.
		/// </summary>
		[System.Text.Json.Serialization.JsonConverter(typeof(JsonConverters.UnixSecondsConverter))]
		[System.Text.Json.Serialization.JsonPropertyName("st")]
		public DateTimeOffset StartTime { get; set; } = DateTimeOffset.MinValue;


		/// <summary>
		/// This is when the sas token expires
		/// </summary>
		[System.Text.Json.Serialization.JsonConverter(typeof(JsonConverters.UnixSecondsConverter))]
		[System.Text.Json.Serialization.JsonPropertyName("se")]
		public DateTimeOffset Expiration { get; set; }


		/// <summary>
		/// a string specifies 1 or more IPAddresses in the formats: (x.x.x.x can be ipv4 or ipv6)
		/// x.x.x.x - single IP Address
		/// x.x.x.x/CIDR - IPAddress with CIDR Range
		/// x.x.x.x-x.x.x.x - IPAddress range
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("sip")]
		public string? AllowedIPAddresses { get; set; }

		/// <summary>
		/// optional parameter to specify the protocol (https/http)
		/// </summary>
		[System.Text.Json.Serialization.JsonPropertyName("spr")]
		public string? Protocol { get; set; }

		/// <summary>
		/// Overridden. returns SAStoken in query string form.
		/// </summary>
		/// <returns>query string</returns>
		public override string ToString()
		{
			return "sv=" + System.Net.WebUtility.UrlEncode(Version) +
				(string.IsNullOrWhiteSpace(Resource) ? "" : ("&sr=" + System.Net.WebUtility.UrlEncode(Resource))) +
				(string.IsNullOrWhiteSpace(Roles) ? "" : ("&sp=" + System.Net.WebUtility.UrlEncode(Roles))) +
				("&sig=" + System.Net.WebUtility.UrlEncode(Signature)) +
				((StartTime == DateTimeOffset.MinValue) ? "" : ("&st=" + StartTime.ToUnixTimeSeconds().ToString())) +
				("&se=" + Expiration.ToUnixTimeSeconds().ToString()) +
				(string.IsNullOrWhiteSpace(Id) ? "" : ("&skn=" + System.Net.WebUtility.UrlEncode(Id))) +
				(string.IsNullOrWhiteSpace(Protocol) ? "" : ("&spr=" + System.Net.WebUtility.UrlEncode(Protocol))) +
				(string.IsNullOrWhiteSpace(AllowedIPAddresses) ? "" : ("&sip=" + System.Net.WebUtility.UrlEncode(AllowedIPAddresses)));
		}

		/// <summary>
		/// returns SAStoken in header format.
		/// </summary>
		/// <returns>KeyValuePair where the key is the header type and the value is the value for the header</returns>
		public KeyValuePair<string,string> ToHttpResponseHeader()
		{
			return new KeyValuePair<string, string>("Authorization", "SharedAccessSignature " + this.ToString());
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
			var stLHS = new DateTime(StartTime.Year, StartTime.Month, StartTime.Day, StartTime.Hour, StartTime.Minute, StartTime.Second);
			var stRHS = new DateTime(token.StartTime.Year, token.StartTime.Month, token.StartTime.Day, token.StartTime.Hour, token.StartTime.Minute, token.StartTime.Second);
			return
							Id == token.Id &&
				(Roles?.Equals(token.Roles, StringComparison.OrdinalIgnoreCase)?? string.IsNullOrWhiteSpace(token.Roles)) &&
				Signature == token.Signature &&
				
				Version == token.Version &&
				(Resource??"") == (token.Resource??"") &&
				(AllowedIPAddresses??"") == (token.AllowedIPAddresses??"") &&
				(Protocol??"") == (token.Protocol??"") &&
				expLHS == expRHS &&
				stLHS == stRHS;
		}

		/// <summary>
		/// checks equality against types: SASToken, SASTokenKey.Id, string==(Id)
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public override bool Equals(object? obj)
		{
            if (obj is null) return false;
			if (obj is SASToken) return Equals((SASToken)obj);
			if (obj is SASTokenKey) return Id == ((SASTokenKey)obj).Id;
			if (obj is IPAddress) return Equals((IPAddress)obj);
			if (obj is string) return Id == (string)obj;
			return base.Equals(obj);
		}

        /// <summary>
        /// Overridden.
        /// </summary>
        /// <returns>Hashcode of Id</returns>
		public override int GetHashCode()
		{
			return Id?.GetHashCode()??0;
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
			//api-version={0}&sp={1}&sig={2}&se={3}&skn={4}
			var qs = QueryHelpers.ParseQuery(value);
			Microsoft.Extensions.Primitives.StringValues version, signature, se, st, skn, roles, resource, allowedIPs, protocol;
			if (!(qs.TryGetValue("sv", out version) || qs.TryGetValue("api-version", out version) || qs.TryGetValue("version", out version) || qs.TryGetValue("v", out version))) { token = Empty; return false; }
			if (!qs.TryGetValue("sig", out signature)) { token = Empty; return false; }
			if (!qs.TryGetValue("se", out se)) { token = Empty; return false; }
			if (!qs.TryGetValue("st", out st)) { st = "0"; }
			if (!qs.TryGetValue("skn", out skn)) { token = Empty; return false; }
			if (!qs.TryGetValue("sp", out roles)) { roles = StringValues.Empty; }
			if (!qs.TryGetValue("sr", out resource)) { roles = StringValues.Empty; }
			if (!qs.TryGetValue("spr", out protocol)) { protocol = StringValues.Empty; }
			if (!qs.TryGetValue("sip", out allowedIPs)) { allowedIPs = StringValues.Empty; }
			long expiration, startTime;
			if (!long.TryParse(se, out expiration)) { token = Empty; return false; }
			if (!long.TryParse(st, out startTime)) { token = Empty; return false; }
			token = new SASToken(skn, roles, resource, allowedIPs, protocol, signature, version, expiration, startTime);
			return true;
		}
	}
}
