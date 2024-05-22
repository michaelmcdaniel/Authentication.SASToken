using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using Authentication.SASToken;

namespace Authentication.SASToken
{
    /// <summary>
    /// Attribute to apply on Controller Classes or Methods to check for Valid SASTokens
    /// </summary>
	public class SASTokenAuthorizationAttribute : ActionFilterAttribute, IAuthorizationFilter
	{
		public const string AuthenticationScheme = "SharedAccessSignature";
		public SASTokenAuthorizationAttribute()
		{
		}

        /// <summary>
        /// Returns 403 if validation fails.
        /// </summary>
        /// <param name="context"></param>
		public void OnAuthorization(AuthorizationFilterContext context)
		{
			ITokenSourceStore tsStore = context.HttpContext.RequestServices.GetService<ITokenSourceStore>();
			Microsoft.Extensions.Logging.ILoggerFactory loggerFactory = context.HttpContext.RequestServices.GetService<Microsoft.Extensions.Logging.ILoggerFactory>();

			SASToken token = context.HttpContext.GetSASToken();
			TokenSource? tokenSource;
			if (!(
					!token.IsEmpty &&
					(tokenSource = tsStore.GetAsync(token).Result).HasValue &&
					tokenSource.Value.Validate(token, context.HttpContext.Request, loggerFactory.CreateLogger<SASTokenAuthorizationAttribute>())
				))
			{
				context.Result = new StatusCodeResult(403);
			}
			else
			{
				var claims = new[] {
					new Claim(ClaimTypes.NameIdentifier, token.Id.ToString()),
					new Claim(ClaimTypes.Expiration, token.Expiration.ToUnixTimeSeconds().ToString()),
					new Claim(ClaimTypes.Uri, tokenSource.Value.Uri.ToString()),
					new Claim(ClaimTypes.Version, token.Version)
				};
				var identity = new ClaimsIdentity(claims, AuthenticationScheme);
				var principal = new ClaimsPrincipal(identity);
				context.HttpContext.User = principal;
			}
		}
	}
}
