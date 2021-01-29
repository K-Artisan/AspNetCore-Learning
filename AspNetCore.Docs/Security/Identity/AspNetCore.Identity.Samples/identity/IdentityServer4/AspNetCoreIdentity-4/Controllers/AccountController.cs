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

        public async Task<ResultVM> Login([FromBody] LoginVM model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    var result = new ResultVM();

                    var signInResult = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, true,
                            lockoutOnFailure: false);


                    result.Status = signInResult == SignInResult.Success ? Status.Success : Status.Error;
                    result.Message = signInResult == SignInResult.Success ? $"Welcome {user.UserName}" : "Invalid login";
                    result.Data = signInResult == SignInResult.Success ? (object)model : $"<li>Invalid login attempt - {signInResult}</li>";

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
    }
}
