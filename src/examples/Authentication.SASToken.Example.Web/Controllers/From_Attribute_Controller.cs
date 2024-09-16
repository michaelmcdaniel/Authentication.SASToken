using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Example.Web.Controllers
{
	[Route("api/attribute-protected")]
	[ApiController]
	public class From_Attribute_Controller : ControllerBase
	{
		[HttpGet]
		[Route("claims")]
		[ResponseCache(Duration = 0)]
		[SASTokenAuthorization]
		public IEnumerable<Models.ClaimModel> claims()
		{
			return User?.Claims?.Select(c => new Models.ClaimModel(c)) ?? new Models.ClaimModel[0];
		}

		[HttpGet]
		[Route("admin-claims")]
		[ResponseCache(Duration = 0)]
		[SASTokenAuthorization(new string[] { "Admin" })]
		public IEnumerable<Models.ClaimModel> AdminClaims()
		{
			return User?.Claims?.Select(c => new Models.ClaimModel(c)) ?? new Models.ClaimModel[0];
		}

		[HttpGet]
		[Route("claim-value")]
		[ResponseCache(Duration = 0)]
		[SASTokenAuthorization]
		public IEnumerable<Models.ClaimModel> claims([FromQuery] [SASTokenResource]string type)
		{
			return User?.Claims?.Where(c=>c.Type== type)?.Select(c => new Models.ClaimModel(c)) ?? new Models.ClaimModel[0];
		}
	}
}
