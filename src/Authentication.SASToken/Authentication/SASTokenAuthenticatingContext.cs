using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

namespace Authentication.SASToken.Authentication
{
    /// <summary>
    /// Authentication Context for a SASToken
    /// </summary>
	public class SASTokenAuthenticatingContext : PrincipalContext<SASTokenAuthenticationOptions>
	{
		/// <summary>
		/// Creates a new instance of the context object.
		/// </summary>
		/// <param name="context">The HTTP request context</param>
		/// <param name="scheme">The scheme data</param>
		/// <param name="options">The handler options</param>
		public SASTokenAuthenticatingContext(
			HttpContext context,
			AuthenticationScheme scheme,
			SASTokenAuthenticationOptions options
			)
			: base(context, scheme, options, null)
		{
		}
	}
}
