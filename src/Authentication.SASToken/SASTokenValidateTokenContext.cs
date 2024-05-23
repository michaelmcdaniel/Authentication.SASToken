using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;

using Microsoft.AspNetCore.Authentication;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
	///<inherited/>
    public class SASTokenValidateTokenContext : PrincipalContext<SASTokenAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new instance of the context object.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        public SASTokenValidateTokenContext(HttpContext context, AuthenticationScheme scheme, SASTokenAuthenticationOptions options)
            : base(context, scheme, options, null)
        {
        }

        /// <summary>
        /// Called to replace the claims principal. The supplied principal will replace the value of the
        /// Principal property, which determines the identity of the authenticated request.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> used as the replacement</param>
        public void ReplacePrincipal(ClaimsPrincipal principal) => Principal = principal;

        /// <summary>
        /// Called to reject the incoming principal. This may be done if the application has determined the
        /// account is no longer active, and the request should be treated as if it was anonymous.
        /// </summary>
        public void RejectPrincipal() => Principal = null;
    }
}
