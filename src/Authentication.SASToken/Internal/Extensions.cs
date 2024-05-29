using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
#nullable enable

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Extensions
{
	/// <summary>
	/// Internal extension methods
	/// </summary>
    public static class Internal_Extensions
    {
        private static readonly DateTimeOffset Max = new DateTimeOffset(9999, 12, 31, 0, 0, 0, 0, TimeSpan.Zero);

		/// <summary>
		/// Returns max DateTime of 9999-12-31 if timespan exceeds it.
		/// </summary>
		/// <param name="value">The timespan</param>
		/// <returns>Max Date</returns>
		public static DateTimeOffset ToMax(this TimeSpan? value)
		{
			if (value == null || (Max - DateTimeOffset.UtcNow).TotalSeconds < value.Value.TotalSeconds) return Max;
			if (value.Value < TimeSpan.Zero) return DateTimeOffset.UtcNow;
			return DateTimeOffset.UtcNow + value.Value;
		}

		/// <summary>
		/// Returns max DateTime of 9999-12-31 if timespan exceeds it.
		/// </summary>
		/// <param name="value">The timespan</param>
		/// <returns>Max Date</returns>
		public static DateTimeOffset ToMax(this TimeSpan value)
		{
			if ((Max - DateTimeOffset.UtcNow).TotalSeconds < value.TotalSeconds) return Max;
			if (value < TimeSpan.Zero) return DateTimeOffset.UtcNow;
			return DateTimeOffset.UtcNow + value;
		}

		/// <summary>
		/// Tries to parse out an ip address and cidr in the format x.x.x.x/cidr
		/// </summary>
		/// <param name="input">string to parse</param>
		/// <param name="ip">valid ip if return true</param>
		/// <param name="cidr">valid cidr if true.  If not cidr present, returns exact max cidr for ipv4=32/ipv6=128</param>
		/// <returns>true if parsed correctly.</returns>
		public static bool TryParseIP_CIDR(string input, out IPAddress? ip, out int cidr)
		{
			string[] parts = input.Split('/');
			cidr = 0;
			IPAddress? temp;
			bool valid = IPAddress.TryParse(parts[0], out temp);
			ip = temp;
			if (valid)
			{
				if (parts.Length == 2)
				{
					valid = int.TryParse(parts[1], out cidr);
					if (valid && ip!.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) return cidr <= 32;
					if (valid && ip!.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) return cidr <= 128;
				}
				else if (ip!.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) cidr = 32;
				else cidr = 128;
			}
			return valid;
			
		}

		/// <summary>
		/// Checks if ipaddress is in given range.
		/// </summary>
		/// <param name="ip">IP Address to check</param>
		/// <param name="ipAddresses">The IP Address ranges</param>
		/// <returns>True if ip address is in range (inclusive)</returns>
		/// <remarks>valid formats include 
		/// x.x.x.x [,x.x.x.x]
		/// x.x.x.x-x.x.x.x
		/// x.x.x.x/cidr
		/// </remarks>
		/// <exception cref="FormatException">throws if the range is invalid</exception>
		public static bool IsInRange(this IPAddress ip, string? ipAddresses)
		{
			if (string.IsNullOrEmpty(ipAddresses) || ipAddresses == "0.0.0.0/0" || ipAddresses == "::/0") return true;
			foreach (var ipRange in ipAddresses.Split(',').Select(ip => ip.Trim()).Where(ip => !string.IsNullOrWhiteSpace(ip)))
			{
				string[] parts = ipRange.Split('-');
				if (parts.Length > 2) throw new FormatException("Invalid ip address range format");
				byte[] address = ip.GetAddressBytes();
				IPAddress? pip;
				int cidr;
				if (parts.Length == 1)
				{
					if (!TryParseIP_CIDR(ipRange, out pip, out cidr) || pip == null) throw new FormatException("Invalid ip address range format");
					int bits = cidr;
					int index = 0;
					byte[] cidrAddress = pip.GetAddressBytes();
					bool failed = false;
					for (; bits >= 8 && !failed; bits -= 8)
					{
						if (address[index] != cidrAddress[index])
							failed = true;
						++index;
					}
					

					if (!failed && bits > 0)
					{
						int mask = (byte)~(255 >> bits);
						if ((address[index] & mask) != (cidrAddress[index] & mask))
							failed = true;
					}

					if (failed) continue;
				}
				else
				{
					if (!IPAddress.TryParse(parts[0], out IPAddress? lower) || !IPAddress.TryParse(parts[1], out IPAddress? upper)) throw new FormatException("Invalid ip address range format");

					bool lowerBoundary = true, upperBoundary = true;
					var lowerBytes = lower.GetAddressBytes();
					var upperBytes = upper.GetAddressBytes();
					bool failed = false;
					for (int i = 0; !failed && i < lowerBytes.Length && (lowerBoundary || upperBoundary); i++)
					{
						if ((lowerBoundary && address[i] < lowerBytes[i]) ||
							(upperBoundary && address[i] > upperBytes[i]))
						{
							failed = true;
						}

						lowerBoundary &= (address[i] == lowerBytes[i]);
						upperBoundary &= (address[i] == upperBytes[i]);
					}
					if (failed) continue;

				}
				return true;
			}
			return false;
		}

		/// <summary>
		/// verifies the given request matches in possible wildchard uri path.
		/// </summary>
		/// <param name="uri">The wildcard path</param>
		/// <param name="request">the request path to verify</param>
		/// <param name="logger">if given, will log the failure reason</param>
		/// <returns>true if the request parts match the given uri</returns>
		public static bool IsMatch(this Uri uri, Uri? request, Microsoft.Extensions.Logging.ILogger? logger = null) => IsMatch(uri, request?.Scheme, request?.Host, request?.Port, new PathString(request?.AbsolutePath??PathString.Empty), logger);

		/// <summary>
		/// verifies the given request matches in possible wildchard uri path.
		/// </summary>
		/// <param name="uri">The wildcard path</param>
		/// <param name="scheme">http/https</param>
		/// <param name="host">host name</param>
		/// <param name="port">port</param>
		/// <param name="path">relative path</param>
		/// <param name="logger">if given, will log the failure reason</param>
		/// <returns>true if the parts match the given uri</returns>
		public static bool IsMatch(this Uri uri, string? scheme, string? host, int? port, PathString? path, Microsoft.Extensions.Logging.ILogger? logger = null)
		{
			if (uri.IsAbsoluteUri)
			{
				if (!string.IsNullOrEmpty(uri.Scheme) && !uri.Scheme.Equals(scheme, StringComparison.OrdinalIgnoreCase))
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: scheme mismatch: source: {1} != {2}", uri, uri.Scheme, scheme);
					return false;
				}

				if (!string.IsNullOrWhiteSpace(uri.Host) && uri.Host != "*" && !uri.Host.Equals(host, StringComparison.OrdinalIgnoreCase))
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: host mismatch: source: {1} != {2}", uri, uri.Host, host);
					return false;
				}

				if (!uri.IsDefaultPort && !uri.Port.Equals(port))
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: port mismatch: source: {1} != {2}", uri, uri.Port, port);
					return false;
				}
			}

			if (((!uri.IsAbsoluteUri && !string.IsNullOrWhiteSpace(uri.OriginalString)) || (uri.IsAbsoluteUri && !string.IsNullOrWhiteSpace(uri.AbsolutePath) && uri.AbsolutePath != "/**")))
			{
				if (path == null || !path.HasValue)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: path mismatch: source: {1} != ", uri, (!uri.IsAbsoluteUri ? uri.OriginalString : uri.AbsolutePath));
					return false;
				}

				// we are going to match the endpoint, given our Uri is in the format of something like /**/name/*startsWith/endsWith*/*contains*/*
				string[] sourceSegments = (!uri.IsAbsoluteUri ? uri.OriginalString : uri.AbsolutePath).Split('/');
				string[] targetSegments = path.Value.ToString().Split('/');
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
							while ((ss = ss.Substring(0, ss.Length - 1)).EndsWith("*")) ;
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
					if (logger != null) logger.LogDebug("Token validation failed: path mismatch: source: {1} != {2}", uri, path);
					return false;
				}

			}

			return true;

		}
    }
}
