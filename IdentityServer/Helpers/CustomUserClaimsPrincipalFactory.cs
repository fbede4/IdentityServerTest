using IdentityServer.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer.Helpers
{
    public class CustomUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<IdentityUser<int>, IdentityRole<int>>
    {
        public CustomUserClaimsPrincipalFactory(
            UserManager<IdentityUser<int>> userManager,
            RoleManager<IdentityRole<int>> roleManager,
            IOptions<IdentityOptions> optionsAccessor) : base(userManager, roleManager, optionsAccessor)
        {
        }

        public async override Task<ClaimsPrincipal> CreateAsync(IdentityUser<int> user)
        {
            var principal = await base.CreateAsync(user);
            var claims = (ClaimsIdentity)principal.Identity;
            claims.AddClaims(new[] {
                new Claim(ClaimTypes.GivenName, user.UserName),
                new Claim(ClaimTypes.Surname, user.UserName),
            });
            return principal;
        }
    }
}
