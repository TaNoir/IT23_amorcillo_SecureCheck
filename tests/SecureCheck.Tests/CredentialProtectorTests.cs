using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

public class CredentialProtectorTests
{
    [Fact]
    public void Protect_and_Unprotect_round_trip_password_without_exposing_plaintext()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var provider = DataProtectionProvider.Create(tempDir, cfg => cfg.SetApplicationName("SecureCheck"));
            var protector = new CredentialProtector(provider);
            const string secret = "Lab$ecureP@ssw0rd!2026";

            var encrypted = protector.Protect(secret);

            Assert.NotEqual(secret, encrypted);
            Assert.DoesNotContain(secret, encrypted, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(secret, protector.Unprotect(encrypted));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    [Fact]
    public void Persisted_keys_decrypt_across_new_provider_instances_simulating_restart()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            const string secret = "RestartTest#99";
            string encrypted;

            {
                var firstProvider = DataProtectionProvider.Create(tempDir, cfg => cfg.SetApplicationName("SecureCheck"));
                var firstProtector = new CredentialProtector(firstProvider);
                encrypted = firstProtector.Protect(secret);
            }

            var secondProvider = DataProtectionProvider.Create(tempDir, cfg => cfg.SetApplicationName("SecureCheck"));
            var secondProtector = new CredentialProtector(secondProvider);

            Assert.Equal(secret, secondProtector.Unprotect(encrypted));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    [Fact]
    public void Tampered_ciphertext_throws_CryptographicException()
    {
        var tempDir = CreateTempDirectory();
        try
        {
            var provider = DataProtectionProvider.Create(tempDir, cfg => cfg.SetApplicationName("SecureCheck"));
            var protector = new CredentialProtector(provider);

            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect("not-valid-protected-payload"));
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
    }

    private static DirectoryInfo CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "SecureCheckTests_" + Guid.NewGuid().ToString("N"));
        return Directory.CreateDirectory(path);
    }
}

