using IdentityServer.Dtos;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Services
{
    public class TokenHandlerService
    {
        private readonly IRefreshTokenService _refreshTokenService;
        private readonly ITokenService _tokenService;
        private readonly IReferenceTokenStore _referenceTokenStore;
        private readonly IUserClaimsPrincipalFactory<IdentityUser<int>> _principalFactory;
        private readonly IdentityServerOptions _options;
        private readonly SignInManager<IdentityUser<int>> _signInManager;
        private readonly UserManager<IdentityUser<int>> _userManager;

        public TokenHandlerService(
            IIdentityServerInteractionService interaction,
            IEventService events,
            IRefreshTokenService refreshTokenService,
            ITokenService tokenService,
            IReferenceTokenStore referenceTokenStore,
            IUserClaimsPrincipalFactory<IdentityUser<int>> principalFactory,
            IdentityServerOptions options,
            SignInManager<IdentityUser<int>> signInManager,
            UserManager<IdentityUser<int>> userManager)
        {
            _refreshTokenService = refreshTokenService;
            _tokenService = tokenService;
            _referenceTokenStore = referenceTokenStore;
            _principalFactory = principalFactory;
            _options = options;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public async Task<TokenDto> GetToken(IdentityUser<int> user, bool refresh)
        {
            var identityPricipal = await _principalFactory.CreateAsync(user);
            var identityUser = new IdentityServerUser(user.Id.ToString())
            {
                AdditionalClaims = identityPricipal.Claims.ToArray(),
                DisplayName = user.UserName,
                AuthenticationTime = DateTime.UtcNow,
                IdentityProvider = IdentityServerConstants.LocalIdentityProvider
            };
            var request = new TokenCreationRequest();
            var client = Config.Clients().First();
            request.Subject = identityUser.CreatePrincipal();
            request.IncludeAllIdentityClaims = true;
            request.ValidatedRequest = new ValidatedRequest();
            request.ValidatedRequest.Subject = request.Subject;
            request.ValidatedRequest.SetClient(client);
            request.Resources = new Resources(Config.IdentityResources(), new List<ApiResource>());
            request.ValidatedRequest.Options = _options;
            request.ValidatedRequest.ClientClaims = identityUser.AdditionalClaims;
            var token = await _tokenService.CreateAccessTokenAsync(request);
            token.Issuer = "...";
            var result = new TokenDto
            {
                AccessToken = await _tokenService.CreateSecurityTokenAsync(token)
            };
            if (refresh)
            {
                result.RefreshToken = await _refreshTokenService.CreateRefreshTokenAsync(identityPricipal, token, client);
            }
            return result;
        }

        public async Task<string> RefreshToken(IdentityUser<int> user)
        {
            var identityPricipal = await _principalFactory.CreateAsync(user);
            var identityUser = new IdentityServerUser(user.Id.ToString())
            {
                AdditionalClaims = identityPricipal.Claims.ToArray(),
                DisplayName = user.UserName,
                AuthenticationTime = DateTime.UtcNow,
                IdentityProvider = IdentityServerConstants.LocalIdentityProvider
            };
            var request = new TokenCreationRequest();
            request.Subject = identityUser.CreatePrincipal();
            request.IncludeAllIdentityClaims = true;
            request.ValidatedRequest = new ValidatedRequest();
            request.ValidatedRequest.Subject = request.Subject;
            request.ValidatedRequest.SetClient(Config.Clients().First());
            request.Resources = new Resources(Config.IdentityResources(), new List<ApiResource>());
            request.ValidatedRequest.Options = _options;
            request.ValidatedRequest.ClientClaims = identityUser.AdditionalClaims;
            var token = await _tokenService.CreateAccessTokenAsync(request);
            token.Issuer = "...";
            return await _refreshTokenService.CreateRefreshTokenAsync(identityPricipal, token, Config.Clients().First());
        }

        public async Task RevokeRefreshToken(string clientId, string refreshToken)
        {
            var token = await _referenceTokenStore.GetReferenceTokenAsync(refreshToken);
            if (token.ClientId == clientId)
            {
                await _referenceTokenStore.RemoveReferenceTokenAsync(refreshToken);
            }
        }
    }
}
