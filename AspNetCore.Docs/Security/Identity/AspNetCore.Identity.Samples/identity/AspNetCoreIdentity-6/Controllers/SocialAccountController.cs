using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AspNetCoreIdentity.Infrastructure.Emails;
using AspNetCoreIdentity.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AspNetCoreIdentity.Controllers
{
    [Route("[controller]/[action]")]
    public class SocialAccountController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _emailSender;

        public SocialAccountController(SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager, IEmailSender emailSender)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = emailSender;
        }

        public IActionResult Index()
        {
            return View("../Home/Index");
        }

        [HttpPost]
        public IActionResult Login(string provider, string returnUrl = null)
        {
            var redirectUrl = Url.Action("Callback", "SocialAccount");
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        [HttpGet]
        public async Task<IActionResult> Callback(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                return RedirectToPage("./", new { ReturnUrl = returnUrl });
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToPage("./", new { ReturnUrl = returnUrl });
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey,
                isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }

            var userEmail = info.Principal.FindFirstValue(ClaimTypes.Email);

            if (string.IsNullOrEmpty(userEmail))
            {
                //return LocalRedirect(
                //    $"{returnUrl}?message=Email scope access is required to add {info.ProviderDisplayName} provider&type=danger");

                ViewBag.ErrorTitle = "登录失败";
                ViewBag.ErrorMessage = $"Email scope access is required to add {info.ProviderDisplayName} provider&type=danger";

                return View("Remind");

            }

            var userDb = await _userManager.FindByEmailAsync(userEmail);

            if (userDb != null)
            {
                // RULE #5
                //由外部提供商认证的用户，但拥有与未确认电子邮件地址相同的现有帐户，则必须确认关联，该关联最终也会自动确认现有帐户。
                if (!userDb.EmailConfirmed)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(userDb);

                    var callbackUrl = Url.Action("ConfirmExternalProvider", "Account",
                        values: new
                        {
                            userId = userDb.Id,
                            code = token,
                            loginProvider = info.LoginProvider,
                            providerDisplayName = info.LoginProvider,
                            providerKey = info.ProviderKey
                        },
                        protocol: Request.Scheme);

                    //await _emailSender.SendEmailAsync(userDb.Email, $"Confirm {info.ProviderDisplayName} external login",
                    //    $"Please confirm association of your {info.ProviderDisplayName} account by clicking <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>here</a>.");

                    return LocalRedirect(
                        $"{returnUrl}?message=External account association with {info.ProviderDisplayName} is pending.Please check your email");
                }

                // Add the external provider
                await _userManager.AddLoginAsync(userDb, info);

                await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey,
                   isPersistent: false, bypassTwoFactor: true);

                //return LocalRedirect(
                //    $"{returnUrl}?message={info.ProviderDisplayName} has been added successfully");

                return LocalRedirect(returnUrl);
            }
            //else //创建一个新用户策略
            //{

            //    var user = new IdentityUser
            //    {
            //        UserName = info.Principal.FindFirstValue(ClaimTypes.Email),
            //        Email = info.Principal.FindFirstValue(ClaimTypes.Email)
            //    };
            //    //如果不存在，则创建一个用户，但是这个用户没有密码。
            //    await _userManager.CreateAsync(user);

            //    //生成电子邮件确认令牌
            //    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            //    //生成电子邮件的确认链接
            //    var confirmationLink = Url.Action("ConfirmEmail", "Account",
            //    new { userId = user.Id, token = token }, Request.Scheme);
            //    //需要注入ILogger<AccountController> _logger;服务，记录生成的URL链接
            //    //_logger.Log(LogLevel.Warning, confirmationLink);
            //    ViewBag.ErrorTitle = "注册成功";
            //    ViewBag.ErrorMessage = $"在你登入系统前,我们已经给您发了一份邮件，需要您先进行邮件验证，点击确认链接即可完成。<br/> 也可以点这里进行邮箱确认{confirmationLink}";
                
            //    return View("Remind");
            //}

            //绑定账号策略
            return LocalRedirect($"/register?associate={userEmail}&loginProvider={info.LoginProvider}&providerDisplayName={info.ProviderDisplayName}&providerKey={info.ProviderKey}");

        }

        [HttpGet]
        public async Task<IActionResult> Providers()
        {
            var schemes = await _signInManager.GetExternalAuthenticationSchemesAsync();

            return Ok(schemes.Select(s => s.DisplayName).ToList());
        }

        [HttpPost]
        [Route("/api/socialaccount/associate")]
        public async Task<ResultVM> Associate([FromBody] AssociateViewModel associate)
        {
            // Create a new account..
            if (!associate.associateExistingAccount)
            {
                var user = new IdentityUser
                { Id = Guid.NewGuid().ToString(), UserName = associate.Username, Email = associate.OriginalEmail };

                var createUserResult = await _userManager.CreateAsync(user);
                if (createUserResult.Succeeded)
                {
                    // Add the Trial claim..
                    Claim trialClaim = new Claim("Trial", DateTime.Now.ToString());
                    await _userManager.AddClaimAsync(user, trialClaim);

                    createUserResult =
                        await _userManager.AddLoginAsync(user,
                            new ExternalLoginInfo(null, associate.LoginProvider, associate.ProviderKey,
                                associate.ProviderDisplayName));
                    if (createUserResult.Succeeded)
                    {
                        // Rule #2
                        user.EmailConfirmed = true;
                        await _userManager.UpdateAsync(user);

                        await _signInManager.ExternalLoginSignInAsync(associate.LoginProvider, associate.ProviderKey, false);

                        return new ResultVM
                        {
                            Status = Status.Success,
                            Message = $"{user.UserName} has been created successfully",
                            Data = new { username = user.UserName }
                        };
                    }
                }

                var resultErrors = createUserResult.Errors.Select(e => "<li>" + e.Description + "</li>");
                return new ResultVM
                {
                    Status = Status.Error,
                    Message = "Invalid data",
                    Data = string.Join("", resultErrors)
                };
            }

            var userDb = await _userManager.FindByEmailAsync(associate.AssociateEmail);

            if (userDb != null)
            {
                // Rule #5
                if (!userDb.EmailConfirmed)
                {
                    return new ResultVM
                    {
                        Status = Status.Error,
                        Message = "Invalid data",
                        Data = $"<li>Associated account (<i>{associate.AssociateEmail}</i>) hasn't been confirmed yet.</li><li>Confirm the account and try again</li>"
                    };
                }

                // Rule #4
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(userDb);

                var callbackUrl = Url.Action("ConfirmExternalProvider", "Account",
                    values: new
                    {
                        userId = userDb.Id,
                        code = token,
                        loginProvider = associate.LoginProvider,
                        providerDisplayName = associate.LoginProvider,
                        providerKey = associate.ProviderKey
                    },
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(userDb.Email, $"Confirm {associate.ProviderDisplayName} external login",
                    $"Please confirm association of your {associate.ProviderDisplayName} account by clicking <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>here</a>.");

                return new ResultVM
                {
                    Status = Status.Success,
                    Message = "External account association is pending. Please check your email"
                };
            }

            return new ResultVM
            {
                Status = Status.Error,
                Message = "Invalid data",
                Data = $"<li>User with email {associate.AssociateEmail} not found</li>"
            };
        }
    }
}
