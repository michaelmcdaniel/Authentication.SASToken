using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http.Extensions;
namespace Authentication.SASToken
{
	public class EndpointValidator
	{
		private readonly ITokenSourceStore _store;
		private readonly ILogger<EndpointValidator> _logger;
		public EndpointValidator(ITokenSourceStore store, ILogger<EndpointValidator> logger)
		{
			_store = store;
			_logger = logger;
		}

		public async Task<bool> IsValidAsync(SASToken token, Uri endpoint = null)
		{
			TokenSource? tokenSource = await _store.GetAsync(token);
			if (tokenSource == null)
			{
				_logger.LogDebug("Token validation failed {0}: token source not found", token);
				return false;
			}
			return tokenSource.Value.Validate(token, endpoint, _logger);
		}

		public async Task<bool> IsValidAsync(SASToken token, Microsoft.AspNetCore.Http.HttpRequest request)
		{
			return await IsValidAsync(token, new Uri(request.GetDisplayUrl()));
		}
	}
}
