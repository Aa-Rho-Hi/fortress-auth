
using OtpNet;
using System.Web;

namespace FortressAuth.Api.Services;

public class MfaService
{
    public (string secret, string otpauthUrl) GenerateSecret(string email, string issuer = "FortressAuth")
    {
        var secret = KeyGeneration.GenerateRandomKey(20);
        var base32 = Base32Encoding.ToString(secret);
        var label = HttpUtility.UrlEncode($"{issuer}:{email}");
        var issuerEnc = HttpUtility.UrlEncode(issuer);
        var otpauth = $"otpauth://totp/{label}?secret={base32}&issuer={issuerEnc}&digits=6&period=30";
        return (base32, otpauth);
    }

    public bool VerifyCode(string base32Secret, string code)
    {
        var secretBytes = Base32Encoding.ToBytes(base32Secret);
        var totp = new Totp(secretBytes, step: 30, totpSize: 6);
        return totp.VerifyTotp(code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);
    }
}
