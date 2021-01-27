using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNetCoreIdentity.Infrastructure.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AspNetCoreIdentity.Controllers
{
    [Route("api/[controller]")]
    public class StreamingController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public StreamingController(UserManager<IdentityUser> manager)
        {
            _userManager = manager;
        }

        [HttpGet]
        [Route("videos")]
        [Authorize(Policy = "TrialOnly")]
        public IActionResult Videos()
        {
            var videos = VideoRepository.Videos.Take(4);

            return Ok(videos);
        }
    }
}
