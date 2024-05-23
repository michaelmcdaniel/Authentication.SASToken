using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Authentication.SASToken
{
    /// <summary>
    /// Authentication Events for SASTokens
    /// </summary>
	public class SASTokenAuthenticationEvents
    {
        /// <summary>
        /// Invoked to validate the principal.
        /// </summary>
        public Func<SASTokenValidateTokenContext, Task> OnValidateToken { get; set; } = context => Task.CompletedTask;
        /// <summary>
        /// Invoked to validate the principal.
        /// </summary>
        public Func<SASTokenAuthenticatingContext, Task> OnAuthenticatingToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked to validate the principal.
        /// </summary>
        public Func<SASTokenAuthenticatedContext, Task> OnAuthenticatedToken { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked to validate the principal.
        /// </summary>
        public Func<ForbiddenContext, Task> OnForbidden { get; set; } = context => Task.CompletedTask;



        private static bool IsAjaxRequest(HttpRequest request)
        {
            return string.Equals(request.Query["X-Requested-With"], "XMLHttpRequest", StringComparison.Ordinal) ||
                string.Equals(request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.Ordinal);
        }

        /// <summary>
        /// Invoked to validate the principal.
        /// </summary>
        /// <param name="context">The <see cref="CookieValidatePrincipalContext"/>.</param>
        public virtual Task ValidateToken(SASTokenValidateTokenContext context) => OnValidateToken(context);


        /// <summary>
        /// Invoked during sign in.
        /// </summary>
        /// <param name="context">The <see cref="CookieSigningInContext"/>.</param>
        public virtual Task Authenticating(SASTokenAuthenticatingContext context) => OnAuthenticatingToken(context);

        /// <summary>
        /// Invoked after sign in has completed.
        /// </summary>
        /// <param name="context">The <see cref="CookieSignedInContext"/>.</param>
        public virtual Task Authenticated(SASTokenAuthenticatedContext context) => OnAuthenticatedToken(context);

        /// <summary>
        /// Invoked if Authorization fails and results in a Forbidden response
        /// </summary>
        public virtual Task Forbidden(ForbiddenContext context) => OnForbidden(context);
    }
}
