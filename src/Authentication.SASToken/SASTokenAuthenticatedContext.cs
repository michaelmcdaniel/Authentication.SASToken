using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;



namespace Authentication.SASToken
{
    /// <summary>
    /// Authentication Context for SASTokens
    /// </summary>
	public class SASTokenAuthenticatedContext : PrincipalContext<SASTokenAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="scheme">The scheme data</param>
        /// <param name="options">The handler options</param>
        /// <param name="principal">Initializes Principal property</param>
        public SASTokenAuthenticatedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            SASTokenAuthenticationOptions options,
            ClaimsPrincipal principal
            //, AuthenticationProperties properties
            )
            : base(context, scheme, options, null)//, properties)
        {
            Principal = principal;
        }
    }
}
