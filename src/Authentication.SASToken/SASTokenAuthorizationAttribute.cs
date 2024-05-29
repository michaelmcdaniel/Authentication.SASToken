using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using mcdaniel.ws.AspNetCore.Authentication.SASToken;
using System.Linq;
using System.Collections.Generic;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
    /// <summary>
    /// Attribute to apply on Controller Classes or Methods to check for Valid SASTokens
    /// </summary>
	public class SASTokenAuthorizationAttribute : ActionFilterAttribute, IAuthorizationFilter
	{
		private IEnumerable<string> _roles = null;
		private string _resource = null;
		/// <summary>
		/// Validates endpoint.
		/// </summary>
		public SASTokenAuthorizationAttribute()
		{
		}

		/// <summary>
		/// Validates endpoint and requires any of the given roles.  If no roles are given all roles will be allowed.
		/// </summary>
		/// <param name="roles">list of roles to require</param>
		public SASTokenAuthorizationAttribute(IEnumerable<string> roles)
		{
			_roles = roles;
		}

		/// <summary>
		/// Validates endpoint and requires the resource and any of the given roles.  If no roles are given all roles will be allowed.
		/// </summary>
		/// <param name="resource">resource required for token</param>
		/// <param name="roles">list of roles to require</param>
		public SASTokenAuthorizationAttribute(string resource, IEnumerable<string> roles)
		{
			_resource = resource;
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
					tokenKey.Value.Validate(token, context.HttpContext.Request, _roles, _resource, context.HttpContext.Connection.RemoteIpAddress, loggerFactory.CreateLogger<SASTokenAuthorizationAttribute>())
				))
			{
				context.Result = new StatusCodeResult(403);
			}
			else
			{
				context.HttpContext.User = tokenKey.Value.ToClaimsPrincipal(token, SASTokenAuthenticationDefaults.AuthenticationScheme);
            }
		}
	}
}
