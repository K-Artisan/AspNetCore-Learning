using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNetCoreIdentity.Models;
using AspNetCoreIdentity.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace AspNetCoreIdentity.Controllers
{
    [Route("api/[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AccountController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }


        public IActionResult Index()
        {
            return View();
        }


        [HttpPost]
        public async Task<ResultVM> Register([FromBody] RegisterVM model)
        {
            if (ModelState.IsValid)
            {
                IdentityResult result = null;

                //查找用户
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user != null)
                {
                    return new ResultVM
                    {
                        Status = Status.Error,
                        Message = "Invalid data",
                        Data = "<li>User already exists</li>"
                    };
                }

                user = new IdentityUser
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = model.UserName,
                    Email = model.Email
                };

                //创建用户
                result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    //添加Claim
                    if (model.StartFreeTrial)
                    {
                        Claim trialClaim = new Claim("Trial", DateTime.Now.ToString());
                        await _userManager.AddClaimAsync(user, trialClaim);
                    }
                    else if (model.IsAdmin)
                    {
                        //当数据库没有"Admin"对应的Role，不添加
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }

                    return new ResultVM
                    {
                        Status = Status.Success,
                        Message = "User Created",
                        Data = user
                    };
                }
                else
                {
                    var resultErrors = result.Errors.Select(e => "<li>" + e.Description + "</li>");
                    return new ResultVM
                    {
                        Status = Status.Error,
                        Message = "Invalid data",
                        Data = string.Join("", resultErrors)
                    };
                }
            }

            var errors = ModelState.Keys.Select(e => "<li>" + e + "</li>");
            return new ResultVM
            {
                Status = Status.Error,
                Message = "Invalid data",
                Data = string.Join("", errors)
            };
        }


        #region 登录

        [HttpGet]
        public async Task<IActionResult> LoginAsync(string returnUrl)
        {
            LoginVM model = new LoginVM
            {
                ReturnUrl = returnUrl,
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };

            return View(model);
        }

        [HttpPost]
        public async Task<ResultVM> Login([FromBody] LoginVM model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user != null)
                {
                    var result = new ResultVM();

                    if (await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        // Rule #1
                        if (!await _signInManager.CanSignInAsync(user))
                        {
                            result.Status = Status.Error;
                            result.Data = "<li>Email confirmation required</li>";

                            return result;
                        }

                        var signInResult = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, true,
                            lockoutOnFailure: false);

                        if (signInResult.RequiresTwoFactor)
                        {
                            result.Status = Status.Success;
                            result.Message = "Enter the code generated by your authenticator app";
                            result.Data = new { requires2FA = true };
                            return result;
                        }

                        result.Status = signInResult == SignInResult.Success ? Status.Success : Status.Error;
                        result.Message = signInResult == SignInResult.Success ? $"Welcome {user.UserName}" : "Invalid login";
                        result.Data = signInResult == SignInResult.Success ? (object)model : $"<li>Invalid login attempt - {signInResult}</li>";

                        return result;
                    }

                    result.Status = Status.Error;
                    result.Data = $"<li>Invalid Username or Password</li>";

                    return result;
                }

                return new ResultVM
                {
                    Status = Status.Error,
                    Message = "Invalid data",
                    Data = "<li>Invalid Username or Password</li>"
                };
            }

            var errors = ModelState.Keys.Select(e => "<li>" + e + "</li>");
            return new ResultVM
            {
                Status = Status.Error,
                Message = "Invalid data",
                Data = string.Join("", errors)
            };
        }


        #endregion

        [HttpGet]
        [Authorize]
        public async Task<UserClaims> Claims()
        {
            var loggedInUser = await _userManager.GetUserAsync(User);
            var userClaims = await _userManager.GetClaimsAsync(loggedInUser);
            var claims = userClaims.Union(User.Claims)
                .GroupBy(c => c.Type)
                .Select(c => new ClaimVM
                {
                    Type = c.First().Type,
                    Value = c.First().Value
                });

            return new UserClaims
            {
                UserName = User.Identity.Name,
                Claims = claims
            };
        }

        [HttpGet]
        public async Task<UserStateVM> Authenticated()
        {
            return new UserStateVM
            {
                IsAuthenticated = User.Identity.IsAuthenticated,
                Username = User.Identity.IsAuthenticated ? User.Identity.Name : string.Empty
            };
        }

        [HttpGet]
        [Authorize]
        public async Task<Object> Roles()
        {
            var loggedInUser = await _userManager.GetUserAsync(User);
            var userRoles = await _userManager.GetRolesAsync(loggedInUser);

            return new
            {
                UserName = User.Identity.Name,
                Roles = String.Join(",", userRoles)
            };
        }

        [HttpPost]
        public async Task SignOut()
        {
            /*
        public virtual async Task SignOutAsync()
        {
            await Context.SignOutAsync(IdentityConstants.ApplicationScheme);
            await Context.SignOutAsync(IdentityConstants.ExternalScheme);
            await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
        }
             */
            await _signInManager.SignOutAsync();
        }

        #region 邮箱确认
        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        [HttpGet]

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (userId == null || token == null)
            {
                return RedirectToAction("index", "home");
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                ViewBag.ErrorMessage = $"当前{userId}无效";
                return View("NotFound");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                return View();
            }

            ViewBag.ErrorTitle = "您的电子邮箱还未进行验证";
            return View("Error");
        }



        #endregion

        #region 获取支持第三方身份提供商

        [HttpGet]
        public async Task<IActionResult> Providers()
        {
            var schemes = await _signInManager.GetExternalAuthenticationSchemesAsync();

            return Ok(schemes.Select(s => s.DisplayName).ToList());
        }

        #endregion

        #region 第三方身份提供商关联本地账号确认邮箱

        [HttpGet]
        [Route("/account/ConfirmExternalProvider")]
        public async Task<IActionResult> ConfirmExternalProvider(string userId, string code,
    string loginProvider, string providerDisplayName, string providerKey)
        {
            var user = await _userManager.FindByIdAsync(userId);

            // This comes from an external provider so we can confirm the email as well
            var confirmationResult = await _userManager.ConfirmEmailAsync(user, code);
            if (!confirmationResult.Succeeded)
                return new LocalRedirectResult($"/?message={providerDisplayName} failed to associate&type=danger");

            var newLoginResult = await _userManager.AddLoginAsync(user,
                new ExternalLoginInfo(null, loginProvider, providerKey,
                    providerDisplayName));

            if (!newLoginResult.Succeeded)
                return new LocalRedirectResult($"/?message={providerDisplayName} failed to associate&type=danger");

            var result = await _signInManager.ExternalLoginSignInAsync(loginProvider, providerKey,
                isPersistent: false, bypassTwoFactor: true);
            return new LocalRedirectResult($"/?message={providerDisplayName} has been added successfully");
        }

        #endregion

        #region 设置密码

        [HttpPost]
        [Authorize]
        public async Task<ResultVM> ManagePassword([FromBody] UpdatePasswordVM updatePassword)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);

                /* This will set the password only if it's NULL,源代码如下：
                var hash = await passwordStore.GetPasswordHashAsync(user, CancellationToken);
                if (hash != null)
                {
                    Logger.LogWarning(1, "User already has a password.");
                    return IdentityResult.Failed(ErrorDescriber.UserAlreadyHasPassword());
                }
                */
                var result = await _userManager.AddPasswordAsync(user, updatePassword.Password);

                if (result.Succeeded)
                {
                    return new ResultVM
                    {
                        Status = Status.Success,
                        Message = "Password has been updated successfully"
                    };
                }

                var errors = result.Errors.Select(e => e.Description).Select(e => "<li>" + e + "</li>");

                return new ResultVM
                {
                    Status = Status.Error,
                    Message = "Invalid data",
                    Data = string.Join("", errors)
                };
            }
            else
            {
                var errors = ModelState.Keys.Select(e => "<li>" + e + "</li>");
                return new ResultVM
                {
                    Status = Status.Error,
                    Message = "Invalid data",
                    Data = string.Join("", errors)
                };
            }
        }

        #endregion


    }
}
