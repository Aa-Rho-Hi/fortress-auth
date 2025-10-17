
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using FortressAuth.Api.Data;
using FortressAuth.Api.DTOs;
using FortressAuth.Api.Models;
using FortressAuth.Api.Services;

namespace FortressAuth.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(AppDbContext db, PasswordService pw, MfaService mfa) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req)
    {
        if (await db.Users.AnyAsync(u => u.Email == req.Email))
            return Conflict(new { error = "Email already registered" });

        var user = new User { Email = req.Email, PasswordHash = pw.Hash(req.Password), Role = "User" };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return Created("", new { id = user.Id, email = user.Email });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromServices] TokenService tokens, [FromBody] LoginRequest req)
    {
        var user = await db.Users.Include(u => u.RefreshTokens).FirstOrDefaultAsync(u => u.Email == req.Email);
        if (user is null || !pw.Verify(req.Password, user.PasswordHash))
            return Unauthorized(new { error = "Invalid credentials" });

        if (user.MfaEnabled)
        {
            if (string.IsNullOrWhiteSpace(req.Otp) || !mfa.VerifyCode(user.MfaSecret!, req.Otp!))
                return Unauthorized(new { error = "MFA required", mfa_required = true });
        }

        var at = tokens.CreateAccessToken(user);
        var rt = tokens.CreateRefreshToken();
        user.RefreshTokens.Add(new RefreshToken { Token = rt, ExpiresAt = DateTime.UtcNow.AddDays(7) });
        await db.SaveChangesAsync();
        return Ok(new { access_token = at, token_type = "Bearer", expires_in = 60*30, refresh_token = rt });
    }

    [Authorize]
    [HttpPost("enable-mfa")]
    public async Task<IActionResult> EnableMfa([FromServices] MfaService svc)
    {
        var email = User.Claims.FirstOrDefault(c => c.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Email)?.Value;
        var user = await db.Users.FirstAsync(u => u.Email == email);
        var (secret, url) = svc.GenerateSecret(user.Email);
        user.MfaSecret = secret;
        await db.SaveChangesAsync();
        return Ok(new EnableMfaResponse(secret, url));
    }

    [Authorize]
    [HttpPost("verify-mfa")]
    public async Task<IActionResult> VerifyMfa([FromBody] Dictionary<string,string> body)
    {
        if (!body.TryGetValue("code", out var code)) return BadRequest(new { error = "code required" });
        var email = User.Claims.FirstOrDefault(c => c.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Email)?.Value;
        var user = await db.Users.FirstAsync(u => u.Email == email);
        if (string.IsNullOrWhiteSpace(user.MfaSecret) || !mfa.VerifyCode(user.MfaSecret, code))
            return Unauthorized(new { error = "Invalid code" });
        user.MfaEnabled = true;
        await db.SaveChangesAsync();
        return Ok(new { mfa_enabled = true });
    }
}
