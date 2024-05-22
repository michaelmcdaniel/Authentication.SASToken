using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication.SASToken.Authentication
{
    /// <summary>
    /// ForbiddenContext for response.
    /// </summary>
	public class ForbiddenContext : ResultContext<SASTokenAuthenticationOptions>
	{
		/// <summary>
		/// Initializes a new instance of <see cref="ForbiddenContext"/>.
		/// </summary>
		/// <inheritdoc />
		public ForbiddenContext(
			HttpContext context,
			AuthenticationScheme scheme,
			SASTokenAuthenticationOptions options)
			: base(context, scheme, options) { }
	}
}
