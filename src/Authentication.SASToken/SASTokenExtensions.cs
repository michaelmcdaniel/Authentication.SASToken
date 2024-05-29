using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
#nullable enable

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
	/// <summary>
	/// Extensions for SASTokens
	/// </summary>
	public static class SASTokenExtensions
	{
		/// <summary>
		/// Extension Method: Gets a SASToken from HttpContext
		/// </summary>
		/// <param name="context">HttpContext</param>
		/// <returns>SASToken if found, otherwise SASToken.Empty</returns>
		public static SASToken GetSASToken(this Microsoft.AspNetCore.Http.HttpContext? context)
		{
			return context?.Request?.GetSASToken()??SASToken.Empty;
		}

        /// <summary>
        /// Gets a SASToken from HttpRequest
        /// </summary>
        /// <param name="request">HttpRequest</param>
        /// <returns>SASToken if found, otherwise SASToken.Empty</returns>
		public static SASToken GetSASToken(this Microsoft.AspNetCore.Http.HttpRequest request)
		{
            if (request is null) return SASToken.Empty;
			Microsoft.Extensions.Primitives.StringValues sv;
			SASToken retVal;
			if (!request.Headers.TryGetValue("Authorization", out sv) || !SASToken.TryParse(sv.ToString(), out retVal))
			{
				retVal = new SASToken(request.QueryString);
			}
			return retVal;
		}

		public static async System.Threading.Tasks.Task<bool> ValidateAsync(this ISASTokenKeyResolver store, HttpContext context, IEnumerable<string>? roles = null, string? resourceOverride = null)
		{
			var token = context.Request.GetSASToken();
			var key = await store.GetAsync(token);
			if (key is null) return false;
			return key.Value.Validate(token, context.Request, roles, resourceOverride, context.Connection.RemoteIpAddress, context.RequestServices.GetService<ILogger<SASTokenKey>>());
		}

		public static async System.Threading.Tasks.Task<bool> ValidateAsync(this ISASTokenKeyStore store, HttpContext context, IEnumerable<string>? roles = null, string? resourceOverride = null)
		{
			var token = context.Request.GetSASToken();
			var key = await store.GetAsync(token);
			if (key is null) return false;
			return key.Value.Validate(token, context.Request, roles, resourceOverride, context.Connection.RemoteIpAddress, context.RequestServices.GetService<ILogger<SASTokenKey>>());
		}

		/// <summary>
		/// Produces claims set from SASToken properties
		/// </summary>
		/// <param name="tokenKey">The SASTokenKey for token</param>
		/// <param name="token">The validated token</param>
		/// <returns>Claim set</returns>
		public static IEnumerable<Claim>? ToClaims(this SASTokenKey tokenKey, SASToken token)
		{
			var claims = new List<Claim>(new[] {
					new Claim(ClaimTypes.NameIdentifier, token.Id??""),
					new Claim(ClaimTypes.Expiration, token.Expiration.ToUnixTimeSeconds().ToString()),
					new Claim(ClaimTypes.Uri, tokenKey.Uri.ToString()),
					new Claim(ClaimTypes.System, token.Resource??tokenKey.Resource??""),
					new Claim(ClaimTypes.Version, token.Version??tokenKey.Version)
				});
			claims.AddRange(token.Roles?.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrEmpty(r)).Select(r => new Claim(ClaimTypes.Role, r)) ?? new Claim[0]);
			return claims;
		}

		/// <summary>
		/// Produces claims identity from the SASToken[Key] properties with scheme
		/// </summary>
		/// <param name="tokenKey">The SASTokenKey for token</param>
		/// <param name="token">The validated token</param>
		/// <param name="scheme">authentication scheme</param>
		/// <returns>ClaimsIdentity</returns>
		public static ClaimsIdentity ToClaimsIdentity(this SASTokenKey tokenKey, SASToken token, string? scheme)
		{
			return new ClaimsIdentity(tokenKey.ToClaims(token), scheme);
		}

		/// <summary>
		/// Produces ClaimsPrincipal from the SASToken[Key] properties with scheme
		/// </summary>
		/// <param name="tokenKey">The SASTokenKey for token</param>
		/// <param name="token">The validated token</param>
		/// <param name="scheme">authentication scheme</param>
		/// <returns>ClaimsPrincipal</returns>
		public static ClaimsPrincipal ToClaimsPrincipal(this SASTokenKey tokenKey, SASToken token, string? scheme)
		{
			return new ClaimsPrincipal(new ClaimsIdentity(tokenKey.ToClaims(token), scheme));
		}
	}
}

