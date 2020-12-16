using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Cookies.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        private bool ValidateLogin(string userName, string password)
        {
            // For this sample, all logins are successful.
            return true;
        }

        [HttpPost]
        public async Task<IActionResult> Login(string userName, string password, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            // Normally Identity handles sign in, but you can do it directly
            if (ValidateLogin(userName, password))
            {
                var claims = new List<Claim>
                {
                    new Claim("user", userName),
                    new Claim("role", "Member")
                };
                var sds = DateTime.Now.ToString();

                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies", "user", "role"));
                //await HttpContext.SignInAsync(claimsPrincipal);
                await HttpContext.SignInAsync(Startup.AuthenticationScheme_Cookie, claimsPrincipal, new AuthenticationProperties
                {
                    /*
                     * IsPersistent默认为false，这时的Cookie是会话Cookie，关闭浏览器后会被删除。
                     * 将IsPersistent设置为true,Cookie变成持久Cookie，关闭浏览器后不会被删除，除非到期后才删除。
                     * 客户端可设置“记住我”与IsPersistent绑定，下次登录可以不用输入用户和密码
                     */
                    IsPersistent = true 
                }) ;

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

        /// <summary>
        /// 访问被拒绝页面
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        public IActionResult AccessDenied(string returnUrl = null)
        {
            return View();
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(Startup.AuthenticationScheme_Cookie);
            return Redirect("/");
        }
    }
}
