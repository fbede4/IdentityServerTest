// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Security.Claims;
using IdentityServer.Helpers;
using IdentityServer.Models;
using IdentityServer.Services;
using IdentityServer4.AccessTokenValidation;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServer
{
    public class Startup
    {
        public IHostingEnvironment Environment { get; }

        public Startup(IHostingEnvironment environment)
        {
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddDbContext<AppDbContext>(o => o.UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=identityserverdb;Trusted_Connection=True;MultipleActiveResultSets=true"));

            services.AddIdentity<IdentityUser<int>, IdentityRole<int>>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 4;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;
            })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders()
                .AddClaimsPrincipalFactory<CustomUserClaimsPrincipalFactory>();

            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddAspNetIdentity<IdentityUser<int>>()
                .AddInMemoryIdentityResources(Config.IdentityResources())
                .AddInMemoryClients(Config.Clients())
                .AddInMemoryApiResources(Config.Apis());

            services.AddAuthentication()
               .AddJwtBearer("Bearer", jwt =>
               {
                   jwt.Authority = "http://localhost:5000";
                   jwt.RequireHttpsMetadata = false;
                   jwt.Audience = "api1";
               });

            services.AddTransient<TokenHandlerService>();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.UseIdentityServer();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}