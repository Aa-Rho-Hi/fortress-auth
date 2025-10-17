
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using FortressAuth.Api.Models;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace FortressAuth.Api.Services;

public class JwtOptions
{
    public string Issuer { get; set; } = "";
    public string Audience { get; set; } = "";
    public int AccessTokenMinutes { get; set; } = 30;
    public int RefreshTokenDays { get; set; } = 7;
}

public class TokenService
{
    private readonly JwtOptions _opts;
    private readonly RSA _rsa;

    public TokenService(RsaKeyService keySvc, IOptions<JwtOptions> options)
    {
        _rsa = keySvc.GetOrCreateKey();
        _opts = options.Value;
    }

    public string CreateAccessToken(User user)
    {
        var creds = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256);
        var claims = new List<Claim> {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Role, user.Role),
        };
        var token = new JwtSecurityToken(
            issuer: _opts.Issuer,
            audience: _opts.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(_opts.AccessTokenMinutes),
            signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }
}
