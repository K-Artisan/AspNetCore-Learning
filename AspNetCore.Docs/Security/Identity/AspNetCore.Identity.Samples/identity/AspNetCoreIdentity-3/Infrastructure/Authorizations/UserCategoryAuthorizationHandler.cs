using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNetCoreIdentity.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace AspNetCoreIdentity.Infrastructure.Authorizations
{
    /*
     Imprerative authorization is very much like the custom provider type 
    but this time you manually check if the user is allowed to access a specific resource. 
    Let’s assume that you want to allow users to add videos on your streaming platform 
    but only to those categories that are registered for. It makes sense right? 
    To implement that type of functionality you will need a requirement and a handler again but not a custom provider.
     
     */
    public class UserCategoryAuthorizationHandler :
        AuthorizationHandler<UserCategoryRequirement, VideoVM>
    {
        private readonly UserManager<IdentityUser> _userManager;

        public UserCategoryAuthorizationHandler(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            UserCategoryRequirement requirement,
            VideoVM resource)
        {
            var loggedInUserTask = _userManager.GetUserAsync(context.User);

            loggedInUserTask.Wait();

            var userClaimsTask = _userManager.GetClaimsAsync(loggedInUserTask.Result);

            userClaimsTask.Wait();

            var userClaims = userClaimsTask.Result;

            if (userClaims.Any(c => c.Type == resource.Category.ToString()))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
