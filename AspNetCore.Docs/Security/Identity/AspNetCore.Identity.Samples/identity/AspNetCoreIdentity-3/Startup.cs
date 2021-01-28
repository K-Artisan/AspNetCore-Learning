using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AspNetCoreIdentity.Infrastructure;
using AspNetCoreIdentity.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using AspNetCoreIdentity.Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using AspNetCoreIdentity.Infrastructure.Authorizations;

namespace AspNetCoreIdentity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            //identity.EfCore
            services.AddDbContext<IdentityDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("AspNetCoreIdentityDb"),
                        optionsBuilder =>
                        optionsBuilder.MigrationsAssembly(typeof(Startup).Assembly.GetName().Name));
            });

            //初始化种子数据
            services.AddScoped<IDbInitializer, DbInitializer>();

            /*-----------------------------------------------Identity----------------------------------------------------
             1. ,通过源码，可知，AddIdentity() 注册如下 cookie认证方案
             The registered sign-in schemes are: Identity.Application, Identity.External, Identity.TwoFactorRememberMe, Identity.TwoFactorUserId
            所不能再使用
             await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);
            进行登录
            改用SignInManager<IdentityUser>的提供的方法:
            -->最终调用：
            SignInManager.SignInWithClaimsAsync(){
                var userPrincipal = await CreateUserPrincipalAsync(user);
                foreach (var claim in additionalClaims)
                {
                    userPrincipal.Identities.First().AddClaim(claim);
                }
                await Context.SignInAsync(IdentityConstants.ApplicationScheme,
                    userPrincipal,
                    authenticationProperties ?? new AuthenticationProperties());
            }

             */
            services.AddIdentity<IdentityUser, IdentityRole>(config => { config.SignIn.RequireConfirmedEmail = false; })
                       .AddEntityFrameworkStores<IdentityDbContext>()
                       //.AddUserManager<AppUserManager>()
                       .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                // Password settings.
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 0;

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings.
                options.User.AllowedUserNameCharacters =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = false;
            });

            services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.Name = ".AspNetCoreIdentityCookie";
                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.Headers["Location"] = context.RedirectUri;
                    context.Response.StatusCode = 401;
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToAccessDenied = context =>
                {
                    context.Response.Headers["Location"] = context.RedirectUri;
                    context.Response.StatusCode = 403;
                    return Task.CompletedTask;
                };
            });

            #region Authorization(授权)

            services.AddAuthorization(options =>
            {
                //基于Claim 的授权
                options.AddPolicy("TrialOnly", policy =>
                {
                    policy.RequireClaim("Trial");
                });

                //基于角色的授权
                options.AddPolicy("AdminOnly", policy =>
                {
                    policy.RequireRole("Admin");
                });
            });


            /*--------自定义授权策略-------
              StreamingCategoryPolicyProvider
             */
            services.AddTransient<IAuthorizationPolicyProvider, StreamingCategoryPolicyProvider>();
            // As always, handlers must be provided for the requirements of the authorization policies
            services.AddTransient<IAuthorizationHandler, StreamingCategoryAuthorizationHandler>(); 
            #endregion
        }


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        // https://stackoverflow.com/questions/42030137/suppress-redirect-on-api-urls-in-asp-net-core/42030138#42030138
        private static Func<RedirectContext<CookieAuthenticationOptions>, Task> ReplaceRedirector(HttpStatusCode statusCode,
            Func<RedirectContext<CookieAuthenticationOptions>, Task> existingRedirector) =>
            context =>
            {
                if (context.Request.Path.StartsWithSegments("/api"))
                {
                    context.Response.StatusCode = (int)statusCode;
                    return Task.CompletedTask;
                }
                return existingRedirector(context);
            };
    }
}
