using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;

namespace Authentication.SASToken
{
    public class SASTokenAuthenticationHandler<T> : AuthenticationHandler<T> where T : SASTokenAuthenticationOptions, new()
    {

        /// <summary>
        /// Initializes a new instance of <see cref="CookieAuthenticationHandler"/>.
        /// </summary>
        /// <param name="options">Accessor to <see cref="CookieAuthenticationOptions"/>.</param>
        /// <param name="logger">The <see cref="ILoggerFactory"/>.</param>
        /// <param name="encoder">The <see cref="UrlEncoder"/>.</param>
        [Obsolete]
        public SASTokenAuthenticationHandler(IOptionsMonitor<T> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }


        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new SASTokenAuthenticationEvents Events
        {
            get { return (SASTokenAuthenticationEvents)base.Events!; }
            set { base.Events = value; }
        }


        /// <summary>
        /// Creates a new instance of the events instance.
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new SASTokenAuthenticationEvents());


        /// <inheritdoc />
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            SASToken? token = Request.GetSASToken();

            // If no authorization header found, nothing to process further
            if (!token.HasValue || token.Value.IsEmpty)
            {
                return AuthenticateResult.NoResult();
            }


            ISASTokenKeyResolver store = await Options.TokenStoreResolverAsync(Context.RequestServices);
            if (store is null)
            {
                return AuthenticateResult.Fail("Token store not found");
            }

            var tokenKey = await store.GetAsync(token.Value);
            if (tokenKey is null)
            {
                return AuthenticateResult.Fail("Token source not found");
            }

            var authenticatingContext = new SASTokenAuthenticatingContext(Context, Scheme, Options);
            await Events.Authenticating(authenticatingContext);
            if (!tokenKey.Value.Validate(token.Value, Request, null, Logger))
            {
                return AuthenticateResult.Fail("Invalid SASToken");
            }
			var claims = new List<Claim>(new[] {
                    new Claim(ClaimTypes.NameIdentifier, token.Value.Id.ToString()),
                    new Claim(ClaimTypes.Expiration, token.Value.Expiration.ToUnixTimeSeconds().ToString()),
                    new Claim(ClaimTypes.Uri, tokenKey.Value.Uri.ToString()),
                    new Claim(ClaimTypes.Version, token.Value.Version)
                });
			claims.AddRange(token.Value.Roles?.Split(',').Select(r => r.Trim()).Where(r => !string.IsNullOrEmpty(r)).Select(r => new Claim(ClaimTypes.Role, r)));

			var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var authenticatedContext = new SASTokenAuthenticatedContext(Context, Scheme, Options, principal);
            await Events.Authenticated(authenticatedContext);
            var tokenValidatedContext = new SASTokenValidateTokenContext(Context, Scheme, Options);
            return AuthenticateResult.Success(new AuthenticationTicket(principal, tokenValidatedContext.Properties, Scheme.Name));
        }




        /// <inheritdoc />
        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var forbiddenContext = new ForbiddenContext(Context, Scheme, Options);
            Response.StatusCode = 403;
            return Events.Forbidden(forbiddenContext);
        }

    }
}
