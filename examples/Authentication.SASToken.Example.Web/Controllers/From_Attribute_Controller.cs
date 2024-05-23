using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.SASToken.Example.Web.Controllers
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
		[SASTokenAuthorization("Admin")]
		public IEnumerable<Models.ClaimModel> AdminClaims()
		{
			return User?.Claims?.Select(c => new Models.ClaimModel(c)) ?? new Models.ClaimModel[0];
		}
	}
}
