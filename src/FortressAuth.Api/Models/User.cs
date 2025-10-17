
using System.ComponentModel.DataAnnotations;

namespace FortressAuth.Api.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [Required, EmailAddress] public string Email { get; set; } = string.Empty;
    [Required] public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User";
    public bool MfaEnabled { get; set; } = false;
    public string? MfaSecret { get; set; }
    public List<RefreshToken> RefreshTokens { get; set; } = new();
}

public class RefreshToken
{
    public int Id { get; set; }
    public Guid UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public bool Revoked { get; set; } = false;
}
