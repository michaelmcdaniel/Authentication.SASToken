﻿using System;
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

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken
{
	/// <summary>
	/// Handles authentication of SASTokens
	/// </summary>
	/// <typeparam name="T">SASTokenAuthenticationOptions</typeparam>
	public class SASTokenAuthenticationHandler<T> : AuthenticationHandler<T> where T : SASTokenAuthenticationOptions, new()
    {
		private ILogger<SASTokenAuthenticationHandler<T>> _logger = null;

		/// <summary>
		/// Initializes a new instance of <see cref="SASTokenAuthenticationOptions"/>.
		/// </summary>
		/// <param name="options">Accessor to <see cref="SASTokenAuthenticationOptions"/>.</param>
		/// <param name="logger">The <see cref="ILoggerFactory"/>.</param>
		/// <param name="encoder">The <see cref="UrlEncoder"/>.</param>
		/// <param name="clock"></param>
		[Obsolete]
        public SASTokenAuthenticationHandler(IOptionsMonitor<T> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
			if (logger != null)
			{
				_logger = logger.CreateLogger<SASTokenAuthenticationHandler<T>>();
			}
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


        /// <summary>
		/// Validates SASToken if available
		/// </summary>
		/// <returns>Failed() or NoResult() if not valid</returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            SASToken? token = Request.GetSASToken();

            // If no authorization header found, nothing to process further
            if (!token.HasValue || token.Value.IsEmpty)
            {
				_logger.LogDebug("No token - AuthenticateResult.NoResult()");
				return AuthenticateResult.NoResult();
            }


            ISASTokenKeyResolver store = await Options.TokenStoreResolverAsync(Context.RequestServices);
            if (store is null)
            {
				_logger.LogError("ISASTokenKeyResolver not found - AuthenticateResult.Fail()");
				return AuthenticateResult.Fail("SASTokenKeyResolver not found");
            }

            var tokenKey = await store.GetAsync(token.Value);
            if (tokenKey is null)
            {
				_logger.LogInformation("SASTokenKey not found - AuthenticateResult.Fail()");
				return AuthenticateResult.Fail("SASTokenKey not found");
            }

            var authenticatingContext = new SASTokenAuthenticatingContext(Context, Scheme, Options);
            await Events.Authenticating(authenticatingContext);
            if (!tokenKey.Value.Validate(token.Value, Request, null, null, Request.HttpContext.Connection.RemoteIpAddress, Logger))
            {
				_logger.LogDebug("SASToken validation failed - AuthenticateResult.Fail()");
				return AuthenticateResult.Fail("Invalid SASToken");
            }
			_logger.LogDebug($"SASToken validation succeeded {0}", token.Value.Id);

			var principal = tokenKey.Value.ToClaimsPrincipal(token.Value, Scheme.Name);
            var authenticatedContext = new SASTokenAuthenticatedContext(Context, Scheme, Options, principal);
			authenticatedContext.Properties.AllowRefresh = false;
			authenticatedContext.Properties.IsPersistent = false;
			authenticatedContext.Properties.ExpiresUtc = token.Value.Expiration;

            await Events.Authenticated(authenticatedContext);
            var tokenValidatedContext = new SASTokenValidateTokenContext(Context, Scheme, Options);
			tokenValidatedContext.Properties.AllowRefresh = false;
			tokenValidatedContext.Properties.ExpiresUtc = token.Value.Expiration;
			tokenValidatedContext.Properties.IsPersistent = false;

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
