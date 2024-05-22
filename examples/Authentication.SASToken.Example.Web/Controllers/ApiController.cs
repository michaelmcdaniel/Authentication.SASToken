using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.SASToken.Example.Web.Controllers
{
    [Route("api")]
    [ApiController]
    public class ApiController : ControllerBase
    {
        [Route("claims")]
        [HttpGet]
        public IEnumerable<Models.ClaimModel> claims()
        {
            return User?.Claims?.Select(c => new Models.ClaimModel(c))??new Models.ClaimModel[0];
        }
    }
}
