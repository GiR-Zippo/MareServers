using MareSynchronos.API.Dto;
using MareSynchronos.API.Dto.Account;
using MareSynchronos.API.Routes;
using MareSynchronosAuthService.Services;
using MareSynchronosShared;
using MareSynchronosShared.Data;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils;
using MareSynchronosShared.Utils.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;

namespace MareSynchronosAuthService.Controllers;

[Route(MareAuth.Auth)]
public class JwtController : AuthControllerBase
{
    private readonly IHttpContextAccessor _accessor;
    private readonly AccountRegistrationService _accountRegistrationService;
    private readonly IConfigurationService<AuthServiceConfiguration> _configuration;

    public JwtController(ILogger<JwtController> logger,
        IHttpContextAccessor accessor, IDbContextFactory<MareDbContext> mareDbContextFactory,
        SecretKeyAuthenticatorService secretKeyAuthenticatorService,
        AccountRegistrationService accountRegistrationService,
        IConfigurationService<AuthServiceConfiguration> configuration,
        IDatabase redisDb, GeoIPService geoIPProvider)
            : base(logger, accessor, mareDbContextFactory, secretKeyAuthenticatorService,
                configuration, redisDb, geoIPProvider)
    {
        _accessor = accessor;
        _accountRegistrationService = accountRegistrationService;
        _configuration = configuration;
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_CreateIdentV2)]
    public async Task<IActionResult> CreateTokenV2(string auth, string charaIdent)
    {
        var tokenResponse = await CreateToken(auth, charaIdent);
        var tokenContent = tokenResponse as ContentResult;
        if (tokenContent == null)
            return tokenResponse;
        return Json(new AuthReplyDto
        {
            Token = tokenContent.Content,
            WellKnown = _configuration.GetValueOrDefault(nameof(AuthServiceConfiguration.WellKnown), string.Empty),
        });
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_Register)]
    public async Task<IActionResult> Register()
    {
        var ua = HttpContext.Request.Headers["User-Agent"][0] ?? "-";
        var ip = _accessor.GetIpAddress();

        // Legacy endpoint: generate a secret key for the user
        var computedHash = StringUtils.Sha256String(StringUtils.GenerateRandomString(64) + DateTime.UtcNow.ToString());
        var hashedKey = StringUtils.Sha256String(computedHash);

        var dto = await _accountRegistrationService.RegisterAccountAsync(ua, ip, hashedKey);

        return Json(new RegisterReplyDto()
        {
            Success = dto.Success,
            ErrorMessage = dto.ErrorMessage,
            UID = dto.UID,
            SecretKey = computedHash
        });
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_RegisterV2)]
    public async Task<IActionResult> RegisterV2(string hashedSecretKey)
    {
        if (string.IsNullOrEmpty(hashedSecretKey)) return BadRequest("No HashedSecretKey");
        if (hashedSecretKey.Length != 64) return BadRequest("Bad HashedSecretKey");
        if (!hashedSecretKey.All(char.IsAsciiHexDigitUpper)) return BadRequest("Bad HashedSecretKey");

        var ua = HttpContext.Request.Headers["User-Agent"][0] ?? "-";
        var ip = _accessor.GetIpAddress();
        return Json(await _accountRegistrationService.RegisterAccountAsync(ua, ip, hashedSecretKey));
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_CreateIdent)]
    public async Task<IActionResult> CreateToken(string auth, string charaIdent)
    {
        using var dbContext = await MareDbContextFactory.CreateDbContextAsync();
        return await AuthenticateInternal(dbContext, auth, charaIdent).ConfigureAwait(false);
    }

    [Authorize(Policy = "Authenticated")]
    [HttpGet(MareAuth.Auth_RenewToken)]
    public async Task<IActionResult> RenewToken()
    {
        using var dbContext = await MareDbContextFactory.CreateDbContextAsync();
        try
        {
            var uid = HttpContext.User.Claims.Single(p => string.Equals(p.Type, MareClaimTypes.Uid, StringComparison.Ordinal))!.Value;
            var ident = HttpContext.User.Claims.Single(p => string.Equals(p.Type, MareClaimTypes.CharaIdent, StringComparison.Ordinal))!.Value;
            var alias = HttpContext.User.Claims.SingleOrDefault(p => string.Equals(p.Type, MareClaimTypes.Alias))?.Value ?? string.Empty;

            if (await dbContext.Auth.Where(u => u.UserUID == uid || u.PrimaryUserUID == uid).AnyAsync(a => a.MarkForBan))
            {
                var userAuth = await dbContext.Auth.SingleAsync(u => u.UserUID == uid);
                await EnsureBan(uid, userAuth.PrimaryUserUID, ident);

                return Unauthorized("Your Mare account is banned.");
            }

            if (await IsIdentBanned(dbContext, ident))
            {
                return Unauthorized("Your XIV service account is banned from using the service.");
            }

            Logger.LogInformation("RenewToken:SUCCESS:{id}:{ident}", uid, ident);
            return await CreateJwtFromId(uid, ident, alias);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "RenewToken:FAILURE");
            return Unauthorized("Unknown error while renewing authentication token");
        }
    }

    protected async Task<IActionResult> AuthenticateInternal(MareDbContext dbContext, string auth, string charaIdent)
    {
        try
        {
            if (string.IsNullOrEmpty(auth)) return BadRequest("No Authkey");
            if (string.IsNullOrEmpty(charaIdent)) return BadRequest("No CharaIdent");

            var ip = HttpAccessor.GetIpAddress();

            var authResult = await SecretKeyAuthenticatorService.AuthorizeAsync(ip, auth);

            return await GenericAuthResponse(dbContext, charaIdent, authResult);
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Authenticate:UNKNOWN");
            return Unauthorized("Unknown internal server error during authentication");
        }
    }
}