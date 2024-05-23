using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.SASToken.Example.Web.Controllers
{
    [Route("api/from-AddSASToken")]
    [ApiController]
	[Authorize]
    public class From_AddSASToken_Controller : ControllerBase
    {
        [Route("claims")]
        [HttpGet]
		[ResponseCache(Duration = 0)]
        public IEnumerable<Models.ClaimModel> claims()
        {
            return User?.Claims?.Select(c => new Models.ClaimModel(c))??new Models.ClaimModel[0];
        }


		[HttpGet]
		[Route("admin-claims")]
		[ResponseCache(Duration = 0)]
		[Authorize(Roles = "Admin")]
		public IEnumerable<Models.ClaimModel> AdminClaims()
		{
			return User?.Claims?.Select(c => new Models.ClaimModel(c)) ?? new Models.ClaimModel[0];
		}

	}
}
