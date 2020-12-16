using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Cookies
{
    /// <summary>
    /// cookie��֤����������
    /// �������ط����Խ������ã�
    /// һ������startup��AddCookie()���ã�
    /// ��һ������/Account/LoginAction�е�HttpContext.SignInAsync()��������á�
    /// 
    /// </summary>
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public static readonly string AuthenticationScheme_Cookie = "YourSchemeName";

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }


        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddAuthentication(AuthenticationScheme_Cookie) // Sets the default scheme to cookies
              .AddCookie(AuthenticationScheme_Cookie, options =>
              {
                  options.AccessDeniedPath = "/account/denied";
                  options.LoginPath = "/account/login";
                  options.ExpireTimeSpan = TimeSpan.FromSeconds(60 * 1);
                  //options.SlidingExpiration = true;
              });
        }

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
    }
}
