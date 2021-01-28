﻿using CustomPolicyProvider.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace CustomPolicyProvider.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize]
        public IActionResult MyClaims()
        {
            return View();
        }

        // View protected with custom parameterized authorization policy
        [MinimumAgeAuthorize(10)]
        public IActionResult MinimumAge10()
        {
            return View("MinimumAge", 10);
        }

        // View protected with custom parameterized authorization policy
        [MinimumAgeAuthorize(50)]
        public IActionResult MinimumAge50()
        {
            return View("MinimumAge", 50);
        }
    }
}
