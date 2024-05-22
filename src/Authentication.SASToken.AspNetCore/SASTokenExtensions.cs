using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
namespace Authentication.SASTokens
{
	public static class SASTokenExtensions
	{
		public static SASToken GetSASToken(this Microsoft.AspNetCore.Http.HttpContext context)
		{
			return context.Request.GetSASToken();
		}

		public static SASToken GetSASToken(this Microsoft.AspNetCore.Http.HttpRequest request)
		{
			Microsoft.Extensions.Primitives.StringValues sv;
			SASToken retVal;
			Uri endpoint = new Uri(request.GetDisplayUrl());
			if (!request.Headers.TryGetValue("Authorization", out sv) || !SASToken.TryParse(sv, endpoint, out retVal))
			{
				retVal = new SASToken(endpoint, request.QueryString);
			}
			return retVal;
		}

	}
}

