using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
#nullable enable

namespace Authentication.SASToken
{
	public static class SASTokenExtensions
	{
        /// <summary>
        /// Extension Method: Gets a SASToken from HttpContext
        /// </summary>
        /// <param name="request">HttpRequest</param>
        /// <returns>SASToken if found, otherwise SASToken.Empty</returns>
		public static SASToken GetSASToken(this Microsoft.AspNetCore.Http.HttpContext? context)
		{
			return context?.Request?.GetSASToken()??SASToken.Empty;
		}

        /// <summary>
        /// Gets a SASToken from HttpRequest
        /// </summary>
        /// <param name="request">HttpRequest</param>
        /// <returns>SASToken if found, otherwise SASToken.Empty</returns>
		public static SASToken GetSASToken(this Microsoft.AspNetCore.Http.HttpRequest request)
		{
            if (request is null) return SASToken.Empty;
			Microsoft.Extensions.Primitives.StringValues sv;
			SASToken retVal;
			if (!request.Headers.TryGetValue("Authorization", out sv) || !SASToken.TryParse(sv, out retVal))
			{
				retVal = new SASToken(request.QueryString);
			}
			return retVal;
		}

	}
}

