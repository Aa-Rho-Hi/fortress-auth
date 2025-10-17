
using System.Security.Cryptography;

namespace FortressAuth.Api.Services;

public class RsaKeyService
{
    private readonly string _keyDir = Path.Combine(AppContext.BaseDirectory, "keys");

    public RSA GetOrCreateKey()
    {
        Directory.CreateDirectory(_keyDir);
        var privPath = Path.Combine(_keyDir, "rsa_private.pem");
        var pubPath = Path.Combine(_keyDir, "rsa_public.pem");
        if (File.Exists(privPath))
        {
            var pem = File.ReadAllText(privPath);
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        else
        {
            var rsa = RSA.Create(2048);
            File.WriteAllText(privPath, PemEncoding.Write("RSA PRIVATE KEY", rsa.ExportRSAPrivateKey()));
            File.WriteAllText(pubPath, PemEncoding.Write("RSA PUBLIC KEY", rsa.ExportRSAPublicKey()));
            return rsa;
        }
    }
}
