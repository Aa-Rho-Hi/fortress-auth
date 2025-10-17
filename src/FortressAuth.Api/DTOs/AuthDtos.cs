
namespace FortressAuth.Api.DTOs;

public record RegisterRequest(string Email, string Password);
public record LoginRequest(string Email, string Password, string? Otp);
public record EnableMfaResponse(string Secret, string OtpAuthUrl);
public record TokenResponse(string access_token, string token_type, int expires_in, string? refresh_token = null);
public record TokenRequest(string grant_type, string? username, string? password, string? client_id, string? client_secret, string? refresh_token, string? otp);
