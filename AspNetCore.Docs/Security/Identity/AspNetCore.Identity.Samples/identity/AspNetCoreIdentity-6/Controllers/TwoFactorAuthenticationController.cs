using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AspNetCoreIdentity.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AspNetCoreIdentity.Controllers
{
    [Route("api/[controller]/[action]")]
    public class TwoFactorAuthenticationController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UrlEncoder _urlEncoder;

        public TwoFactorAuthenticationController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager, UrlEncoder urlEncoder)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _urlEncoder = urlEncoder;
        }

        [HttpGet]
        [Authorize]
        public async Task<AccountDetailsVM> Details()
        {
            var user = await _userManager.GetUserAsync(User);
            var logins = await _userManager.GetLoginsAsync(user);

            return new AccountDetailsVM
            {
                Username = user.UserName,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                PhoneNumber = user.PhoneNumber,
                ExternalLogins = logins.Select(login => login.ProviderDisplayName).ToList(),
                TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user),
                HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null,
                TwoFactorClientRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user),
                RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user)
            };
        }

        #region MyRegion

        [HttpGet]
        [Authorize]
        public async Task<AuthenticatorDetailsVM> SetupAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            var authenticatorDetails = await GetAuthenticatorDetailsAsync(user);

            return authenticatorDetails;
        }

        [HttpGet]
        [Authorize]
        public async Task<List<int>> ValidAutheticatorCodes()
        {
            List<int> validCodes = new List<int>();

            var user = await _userManager.GetUserAsync(User);

            var key = await _userManager.GetAuthenticatorKeyAsync(user);

            var hash = new HMACSHA1(Infrastructure.Identity.Internals.Base32.FromBase32(key));
            var unixTimestamp = Convert.ToInt64(Math.Round((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds));
            var timestep = Convert.ToInt64(unixTimestamp / 30);
            // Allow codes from 90s in each direction (we could make this configurable?)
            for (int i = -2; i <= 2; i++)
            {
                var expectedCode = Infrastructure.Identity.Internals.Rfc6238AuthenticationService.ComputeTotp(hash, (ulong)(timestep + i), modifier: null);
                validCodes.Add(expectedCode);
            }

            return validCodes;
        }

        [HttpPost]
        [Authorize]
        public async Task<ResultVM> VerifyAuthenticator([FromBody] VefiryAuthenticatorVM verifyAuthenticator)
        {
            var user = await _userManager.GetUserAsync(User);
            if (!ModelState.IsValid)
            {
                var errors = GetErrors(ModelState).Select(e => "<li>" + e + "</li>");
                return new ResultVM
                {
                    Status = Status.Error,
                    Message = "Invalid data",
                    Data = string.Join("", errors)
                };
            }

            var verificationCode = verifyAuthenticator.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2FaTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2FaTokenValid)
            {
                return new ResultVM
                {
                    Status = Status.Error,
                    Message = "Invalid data",
                    Data = "<li>Verification code is invalid.</li>"
                };
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);

            var result = new ResultVM
            {
                Status = Status.Success,
                Message = "Your authenticator app has been verified",
            };

            if (await _userManager.CountRecoveryCodesAsync(user) != 0) return result;

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            result.Data = new { recoveryCodes };
            return result;
        }

        #endregion
    }
}
