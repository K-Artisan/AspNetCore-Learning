using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ClaimsTransformation.Controllers
{
    public class AccountController : Controller
    {
        /// <summary>
        /// 登录首页
        /// </summary>
        /// <param name="returnUrl">，
        /// 框架自动把当前未认证成功页面保证在名为ReturnUrl的QueryString字段中</param>
        /// <returns></returns>
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// <summary>
        /// 登录
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
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

                var claimsPrincipal = new ClaimsPrincipal(
                    new ClaimsIdentity(claims,
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        "user",
                        "role"));


                await HttpContext.SignInAsync(claimsPrincipal);
                var authenticateResult =  HttpContext.AuthenticateAsync();

                if (Url.IsLocalUrl(returnUrl))
                {
                    //return Redirect(returnUrl);
                    return LocalRedirect(returnUrl);
                    
                }
                //else
                {
                    return Redirect("/");
                }

            }

            return View();
        }



        private bool ValidateLogin(string userName, string password)
        {
            // For this sample, all logins are successful.
            return true;
        }

        /// <summary>
        /// 登出
        /// </summary>
        /// <returns></returns>
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return Redirect("/");
        }
    }
}
