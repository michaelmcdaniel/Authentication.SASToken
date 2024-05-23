using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http.Extensions;
namespace Authentication.SASToken
{
	/// <summary>
	/// Simple endpoint validator
	/// </summary>
	public class EndpointValidator
	{
		private readonly ISASTokenKeyResolver _store;
		private readonly ILogger<EndpointValidator> _logger;

		/// <summary>
		/// Constructor (Injected)
		/// </summary>
		/// <param name="store"></param>
		/// <param name="logger"></param>
		public EndpointValidator(ISASTokenKeyResolver store, ILogger<EndpointValidator> logger)
		{
			_store = store;
			_logger = logger;
		}

		/// <summary>
		/// Validates the token against the endpoint with given roles
		/// </summary>
		/// <param name="token">the token to validate</param>
		/// <param name="endpoint">The endpoint to check against</param>
		/// <param name="roles">Roles to validate the token has 1 or more of.</param>
		/// <returns></returns>
		public async Task<bool> IsValidAsync(SASToken token, Uri endpoint = null, IEnumerable<string> roles = null)
		{
			SASTokenKey? tokenKey = await _store.GetAsync(token);
			if (tokenKey == null)
			{
				_logger.LogDebug("Token validation failed {0}: token source not found", token);
				return false;
			}
			return tokenKey.Value.Validate(token, endpoint, roles, _logger);
		}

		/// <summary>
		/// Validates the token against the endpoint from an httpRequest with given roles
		/// </summary>
		/// <param name="token">the token to validate</param>
		/// <param name="request">The request endpoint to check against</param>
		/// <param name="roles">Roles to validate the token has 1 or more of.</param>
		/// <returns></returns>
		public async Task<bool> IsValidAsync(SASToken token, Microsoft.AspNetCore.Http.HttpRequest request, IEnumerable<string> roles = null)
		{
			return await IsValidAsync(token, new Uri(request.GetDisplayUrl()), roles);
		}
	}
}
