using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
#nullable enable

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
    internal static class Extensions
    {
        private static readonly DateTimeOffset Max = new DateTimeOffset(9999, 12, 31, 0, 0, 0, 0, TimeSpan.Zero);

        public static DateTimeOffset ToMax(this TimeSpan? value)
        {
            if (value == null || (Max - DateTimeOffset.UtcNow).TotalSeconds < value.Value.TotalSeconds) return Max;
            if (value.Value < TimeSpan.Zero) return DateTimeOffset.UtcNow;
            return DateTimeOffset.UtcNow + value.Value;
        }

		public static bool IsMatch(this Uri uri, Uri request, Microsoft.Extensions.Logging.ILogger? logger = null) => IsMatch(uri, request.Scheme, request.Host, request.Port, new PathString(request.AbsolutePath), logger);

		public static bool IsMatch(this Uri uri, string scheme, string host, int port, PathString path, Microsoft.Extensions.Logging.ILogger? logger = null)
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
				if (!path.HasValue)
				{
					if (logger != null) logger.LogDebug("Token validation failed {0}: path mismatch: source: {1} != ", uri, (!uri.IsAbsoluteUri ? uri.OriginalString : uri.AbsolutePath));
					return false;
				}

				// we are going to match the endpoint, given our Uri is in the format of something like /**/name/*startsWith/endsWith*/*contains*/*
				string[] sourceSegments = (!uri.IsAbsoluteUri ? uri.OriginalString : uri.AbsolutePath).Split('/');
				string[] targetSegments = path.Value.Split('/');
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
