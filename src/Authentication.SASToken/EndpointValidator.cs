using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http.Extensions;
namespace Authentication.SASToken
{
	public class EndpointValidator
	{
		private readonly ISASTokenKeyResolver _store;
		private readonly ILogger<EndpointValidator> _logger;
		public EndpointValidator(ISASTokenKeyResolver store, ILogger<EndpointValidator> logger)
		{
			_store = store;
			_logger = logger;
		}

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

		public async Task<bool> IsValidAsync(SASToken token, Microsoft.AspNetCore.Http.HttpRequest request, IEnumerable<string> roles = null)
		{
			return await IsValidAsync(token, new Uri(request.GetDisplayUrl()), roles);
		}
	}
}
