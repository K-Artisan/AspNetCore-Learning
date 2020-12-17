using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CustomPolicyProvider.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Login(string returnUrl)
        {
            return View();
        }

        private bool ValidateLogin(string userName, string password)
        {
            // For this sample, all logins are successful.
            return true;
        }

        [HttpPost]
        public async Task<IActionResult> Login(string userName, string password, DateTime? birthDate, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            // Normally Identity handles sign in, but you can do it directly
            // In a real - world application, user credentials would need validated before signing in
            if (ValidateLogin(userName, password))
            {
                var claims = new List<Claim>();
                // Add a Name claim and, if birth date was provided, a DateOfBirth claim
                claims.Add(new Claim(ClaimTypes.Name, userName));
                if (birthDate.HasValue)
                {
                    claims.Add(new Claim(ClaimTypes.DateOfBirth, birthDate.Value.ToShortDateString()));
                }

                // 认证后的用户体现为一个`ClaimsPrincipal`对象
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "UserSpecified");
                var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal, new AuthenticationProperties
                {
                    /*
                     * IsPersistent默认为false，这时的Cookie是会话Cookie，关闭浏览器后会被删除。
                     * 将IsPersistent设置为true,Cookie变成持久Cookie，关闭浏览器后不会被删除，除非到期后才删除。
                     * 客户端可设置“记住我”与IsPersistent绑定，下次登录可以不用输入用户和密码
                     */
                    IsPersistent = true
                });

                if (Url.IsLocalUrl(returnUrl))
                {
                    return LocalRedirect(returnUrl);
                }
                else
                {
                    return Redirect("/");
                }
            }

            return View();
        }



        public IActionResult AccessDenied()
        {
            return View();
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Redirect("/");
        }
    }
}
