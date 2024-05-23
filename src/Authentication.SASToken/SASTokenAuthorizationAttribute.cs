using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using Authentication.SASToken;
using System.Linq;
using System.Collections.Generic;

namespace Authentication.SASToken
{
    /// <summary>
    /// Attribute to apply on Controller Classes or Methods to check for Valid SASTokens
    /// </summary>
	public class SASTokenAuthorizationAttribute : ActionFilterAttribute, IAuthorizationFilter
	{
		private IEnumerable<string> _roles;
		/// <summary>
		/// Validates endpoint and requires any of the given roles.  If no roles are given all roles will be allowed.
		/// </summary>
		/// <param name="roles">list of roles to require</param>
		public SASTokenAuthorizationAttribute(params string[] roles)
		{
			_roles = roles;
		}

        /// <summary>
        /// Returns 403 if validation fails.
        /// </summary>
        /// <param name="context"></param>
		public void OnAuthorization(AuthorizationFilterContext context)
		{
			ISASTokenKeyStore tsStore = context.HttpContext.RequestServices.GetService<ISASTokenKeyStore>();
			Microsoft.Extensions.Logging.ILoggerFactory loggerFactory = context.HttpContext.RequestServices.GetService<Microsoft.Extensions.Logging.ILoggerFactory>();

			SASToken token = context.HttpContext.GetSASToken();
			SASTokenKey? tokenKey;
			if (!(
					!token.IsEmpty &&
					(tokenKey = tsStore.GetAsync(token).Result).HasValue &&
					tokenKey.Value.Validate(token, context.HttpContext.Request, _roles, loggerFactory.CreateLogger<SASTokenAuthorizationAttribute>())
				))
			{
				context.Result = new StatusCodeResult(403);
			}
			else
			{
				var claims = new List<Claim>(new[] {
					new Claim(ClaimTypes.NameIdentifier, token.Id.ToString()),
					new Claim(ClaimTypes.Expiration, token.Expiration.ToUnixTimeSeconds().ToString()),
					new Claim(ClaimTypes.Uri, tokenKey.Value.Uri.ToString()),
					new Claim(ClaimTypes.Version, token.Version)
				});
                claims.AddRange(token.Roles?.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrEmpty(r)).Select(r => new Claim(ClaimTypes.Role, r)));
				context.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, SASTokenAuthenticationDefaults.AuthenticationScheme));
            }
		}
	}
}
