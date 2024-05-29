using Microsoft.AspNetCore.Mvc;
using mcdaniel.ws.AspNetCore.Authentication.SASToken;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Example.Web.Controllers
{
	[Route("api/inline")]
	public class From_Inline_Controller(ILogger<From_Inline_Controller> _logger, ISASTokenKeyStore _tokenStore) : Controller
	{

		[HttpGet]
		[Route("claims")]
		[ResponseCache(Duration = 0)]
		public async Task<IActionResult> claims() //[FromQuery(Name = "sv")] string v, [FromQuery] string sig, [FromQuery] long se, [FromQuery] string skn, [FromQuery] string? sp = null, [FromQuery] string? sip = null, [FromQuery] string? sr = null, [FromQuery] string? spr = null, [FromQuery] long st = 0)
		{
			if (! await _tokenStore.ValidateAsync(HttpContext)) return Forbid();

			var token = HttpContext.GetSASToken();
			var tokenKey = await _tokenStore.GetAsync(token);
			return Json(tokenKey!.Value.ToClaims(token)!.Select(c => new Models.ClaimModel(c)) ?? new Models.ClaimModel[0]);
		}

		[HttpGet]
		[Route("admin-claims")]
		[ResponseCache(Duration = 0)]
		public async Task<IActionResult> AdminClaims([FromQuery(Name = "sv")] string v, [FromQuery] string sig, [FromQuery] long se, [FromQuery] string skn, [FromQuery] string? sp = null, [FromQuery] string? sip = null, [FromQuery] string? sr = null, [FromQuery] string? spr = null, [FromQuery] long st = 0)
		{
			string[] anyUserInRoles = new string[] { "Admin", "PowerUsers" };
			if (!await _tokenStore.ValidateAsync(HttpContext, anyUserInRoles)) return Forbid();

			// or build it from scratch
			var token = new SASToken()
			{
				Id = skn,
				Expiration = DateTimeOffset.FromUnixTimeSeconds(se),
				Signature = sig,
				Roles = sp,
				Version = v,
				AllowedIPAddresses = sip,
				Protocol = spr,
				Resource = sr,
				StartTime = st == 0 ? DateTimeOffset.MinValue : DateTimeOffset.FromUnixTimeSeconds(st)
			};
			var tokenKey = await _tokenStore.GetAsync(token);
			
			return Json(tokenKey!.Value.ToClaims(token)!.Select(c => new Models.ClaimModel(c)) ?? new Models.ClaimModel[0]);
		}
	}
}
