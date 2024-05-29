using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
#nullable enable
namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
	/// <summary>
	/// Options for SASToken Creation from SASTokenKey
	/// </summary>
	public struct SASTokenOptions
	{
		/// <summary>
		/// The start when the token will be valid
		/// </summary>
		public DateTimeOffset? StartTime { get; set; }

		/// <summary>
		/// The absolute expiration of the token
		/// </summary>
		public DateTimeOffset? Expiration { get; set; }

		/// <summary>
		/// List of roles that the token can be used for
		/// </summary>
		public IEnumerable<string>? Roles { get; set; }

		/// <summary>
		/// The resource that this token is for
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
		/// Allowed protocols ex. http,https
		/// </summary>
		public string? Protocol { get; set; }
	}
}
