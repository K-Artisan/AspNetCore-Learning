using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            Environment = env;

        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }


        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            bool useInMemoryStores = bool.Parse(Configuration["UseInMemoryStores"]);
            var connectionString = Configuration.GetConnectionString("IdentityServerConnection");

            #region AspNetCore Identity
            services.AddDbContext<ApplicationDbContext>(options =>
                {
                    if (useInMemoryStores)
                    {
                        options.UseInMemoryDatabase("IdentityServerDb");
                    }
                    else
                    {
                        options.UseSqlServer(connectionString);
                    }
                });

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            #endregion

            #region IdentityServer4
            /*---------------------------------------------------------------------------------
             * do is to register the required IdentityServer services and DbContext stores.
             * 
             * IdentityServer publishes a discovery document：
             * http://localhost:5005/.well-known/openid-configuration
             * 
             */

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
            // this adds the config data from DB (clients, resources)
            .AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = opt =>
                {
                    if (useInMemoryStores)
                    {
                        opt.UseInMemoryDatabase("IdentityServerDb");
                    }
                    else
                    {
                        opt.UseSqlServer(connectionString, b => b.MigrationsAssembly("IdentityServer"));
                    }
                };
            })
            // this adds the operational data from DB (codes, tokens, consents)
            .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = opt =>
                {
                    if (useInMemoryStores)
                    {
                        opt.UseInMemoryDatabase("IdentityServerDb");
                    }
                    else
                    {
                        opt.UseSqlServer(connectionString, b => b.MigrationsAssembly("IdentityServer"));
                    }
                };

                // this enables automatic token cleanup. this is optional.
                options.EnableTokenCleanup = true;
            })
            .AddAspNetIdentity<IdentityUser>();
            /*此示例中我们不使用内存存储，而是使用EF，将Config的配置使用
              DatabaseInitializer进行数据库初始化
            */
            //.AddInMemoryIdentityResources(Config.GetIdentityResources())
            //.AddInMemoryApiResources(Config.GetApis())
            //.AddInMemoryClients(Config.GetClients()); ;

            if (Environment.IsDevelopment())
            {
                //builder.AddDeveloperSigningCredential() which creates a temporary key for signing tokens. 
                //It’s OK for development but you need to be replace it with a valid persistent key when moving to production environment.
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                throw new Exception("need to configure key material");
            }

            #endregion

            services.AddAuthentication();
            services.AddControllersWithViews();


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
            app.UseIdentityServer();

            app.UseRouting();

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
