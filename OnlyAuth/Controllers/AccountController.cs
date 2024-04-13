using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OnlyAuth.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login(string ReturnUrl)
        {
            ViewBag.ReturnUrl = ReturnUrl;
            return View();
        }

        [HttpGet]
        public IActionResult AccessDenied(string ReturnUrl)
        {
            return RedirectToAction("/Account/Login");
        }
        [HttpPost]
        public IActionResult LoginAsync(string userName, string password, string ReturnUrl)
        {
            if (userName == "mahesh" &&
                password == "mahesh"
                )
            {
                List<Claim> claims = new List<Claim>() {
                    new Claim(ClaimTypes.NameIdentifier, userName),
                    new Claim(ClaimTypes.Role,"Admin")

                };

                ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                ClaimsPrincipal principal = new ClaimsPrincipal(identity);
                HttpContext.SignInAsync(principal);
                if (ReturnUrl == null)
                {
                    return Redirect("/Home/Index");
                }
                return Redirect(ReturnUrl);
            }
            else return View();
        }
    }
}
