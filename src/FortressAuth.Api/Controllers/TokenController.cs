
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FortressAuth.Api.DTOs;
using FortressAuth.Api.Data;
using FortressAuth.Api.Services;
using FortressAuth.Api.Models;

namespace FortressAuth.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TokenController(AppDbContext db, PasswordService pw, TokenService tokens, MfaService mfa) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Token([FromForm] TokenRequest req)
    {
        switch (req.grant_type)
        {
            case "password":
                if (string.IsNullOrWhiteSpace(req.username) || string.IsNullOrWhiteSpace(req.password))
                    return BadRequest(new { error = "invalid_request" });
                var user = await db.Users.Include(u=>u.RefreshTokens).FirstOrDefaultAsync(u => u.Email == req.username);
                if (user is null || !pw.Verify(req.password, user.PasswordHash))
                    return Unauthorized(new { error = "invalid_grant" });

                if (user.MfaEnabled && (string.IsNullOrWhiteSpace(req.otp) || !mfa.VerifyCode(user.MfaSecret!, req.otp!)))
                    return Unauthorized(new { error = "mfa_required" });

                var at = tokens.CreateAccessToken(user);
                var rt = tokens.CreateRefreshToken();
                user.RefreshTokens.Add(new RefreshToken { Token = rt, ExpiresAt = DateTime.UtcNow.AddDays(7) });
                await db.SaveChangesAsync();
                return Ok(new TokenResponse(at, "Bearer", 60*30, rt));

            case "client_credentials":
                var cfgId = Environment.GetEnvironmentVariable("CLIENT_ID") ?? "demo-client";
                var cfgSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? "demo-secret";
                if (req.client_id != cfgId || req.client_secret != cfgSecret)
                    return Unauthorized(new { error = "invalid_client" });
                var svcUser = await db.Users.FirstOrDefaultAsync(u => u.Email == "service@fortress.local");
                if (svcUser is null)
                {
                    svcUser = new User { Email = "service@fortress.local", PasswordHash = pw.Hash(Guid.NewGuid().ToString()), Role = "Service" };
                    db.Users.Add(svcUser); await db.SaveChangesAsync();
                }
                var svcToken = tokens.CreateAccessToken(svcUser);
                return Ok(new TokenResponse(svcToken, "Bearer", 60*30, null));

            case "refresh_token":
                if (string.IsNullOrWhiteSpace(req.refresh_token)) return BadRequest(new { error = "invalid_request" });
                var owner = await db.Users.Include(u=>u.RefreshTokens).FirstOrDefaultAsync(u => u.RefreshTokens.Any(rt => rt.Token == req.refresh_token && !rt.Revoked && rt.ExpiresAt > DateTime.UtcNow));
                if (owner is null) return Unauthorized(new { error = "invalid_grant" });
                var newAt = tokens.CreateAccessToken(owner);
                var newRt = tokens.CreateRefreshToken();
                owner.RefreshTokens.Add(new RefreshToken { Token = newRt, ExpiresAt = DateTime.UtcNow.AddDays(7) });
                var old = owner.RefreshTokens.First(rt => rt.Token == req.refresh_token);
                old.Revoked = true;
                await db.SaveChangesAsync();
                return Ok(new TokenResponse(newAt, "Bearer", 60*30, newRt));

            default:
                return BadRequest(new { error = "unsupported_grant_type" });
        }
    }
}
