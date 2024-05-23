using mcdaniel.ws.AspNetCore.Authentication.SASToken.Example.Web.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace mcdaniel.ws.AspNetCore.Authentication.SASToken.Example.Web.Controllers
{
    public class HomeController(ILogger<HomeController> _logger, ISASTokenKeyStore _tokenStore) : Controller
    {

        public async Task<IActionResult> Index()
        {
            return View(await _tokenStore.GetAllAsync());
        }

        [ResponseCache(Duration = 0, NoStore = true)]
        public async Task<IActionResult> Token([FromQuery]string id, [FromQuery]string role)
        {
            var token = (await _tokenStore.GetAsync(id))?.ToToken((role??"").Split(','));
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
