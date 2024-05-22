using Authentication.SASToken.Example.Web.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Authentication.SASToken.Example.Web.Controllers
{
    public class HomeController(ILogger<HomeController> _logger, ITokenSourceStore _tokenSourceStore) : Controller
    {

        public async Task<IActionResult> Index()
        {
            return View(await _tokenSourceStore.GetAllAsync());
        }

        [ResponseCache(Duration = 0, NoStore = true)]
        public async Task<IActionResult> Token([FromQuery]Guid id)
        {
            var token = (await _tokenSourceStore.GetAsync(id))?.ToToken();
            if (token is null)
            {
                _logger.LogWarning($"TokenSource not found for id: {id}");
            }
            else
            {
                _logger.LogInformation($"Token generated from TokenSource: {id}\r\n{token.ToString()}");
            }
            return Json(new { token = token.ToString(), expires = token?.Expiration.ToUnixTimeSeconds()??0 });
        }

        public IActionResult AccessDenied()
        {
            return StatusCode(403);
        }
    }
}
