using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

/// <summary>
/// Verifies the exact Data Protection setup used by Program.cs.
/// </summary>
public class DataProtectionConfigTests
{
    [Fact]
    public void Key_files_are_encrypted_at_rest_with_DPAPI()
    {
        var keysDir = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "SecureCheckKeys_" + Guid.NewGuid().ToString("N")));
        try
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSecureCheckDataProtection(keysDir);

            using (var sp = services.BuildServiceProvider())
            {
                // Protecting something forces a key to be created on disk.
                var protector = new CredentialProtector(sp.GetRequiredService<IDataProtectionProvider>());
                var encrypted = protector.Protect("KeyAtRest#1");
                Assert.Equal("KeyAtRest#1", protector.Unprotect(encrypted));
            }

            var keyXml = File.ReadAllText(Assert.Single(keysDir.GetFiles("key-*.xml")).FullName);
            var doc = XDocument.Parse(keyXml);
            var encryptedSecret = doc.Descendants().SingleOrDefault(e => e.Name.LocalName == "encryptedSecret");

            Assert.NotNull(encryptedSecret);
            Assert.Contains("DpapiXmlDecryptor", (string?)encryptedSecret!.Attribute("decryptorType") ?? string.Empty);
            // When DPAPI encryption is active, the raw <masterKey> element is replaced by <encryptedSecret>.
            Assert.DoesNotContain(doc.Descendants(), e => e.Name.LocalName == "masterKey");
            Assert.DoesNotContain("unencrypted", keyXml, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            keysDir.Delete(recursive: true);
        }
    }

    [Fact]
    public void Credentials_still_decrypt_after_restart_with_DPAPI_protected_keys()
    {
        var keysDir = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), "SecureCheckKeys_" + Guid.NewGuid().ToString("N")));
        try
        {
            string encrypted;
            using (var first = BuildProvider(keysDir))
            {
                encrypted = new CredentialProtector(first.GetRequiredService<IDataProtectionProvider>()).Protect("Restart#2026");
            }

            using var second = BuildProvider(keysDir);
            var protector = new CredentialProtector(second.GetRequiredService<IDataProtectionProvider>());

            Assert.Equal("Restart#2026", protector.Unprotect(encrypted));
        }
        finally
        {
            keysDir.Delete(recursive: true);
        }
    }

    private static ServiceProvider BuildProvider(DirectoryInfo keysDir)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecureCheckDataProtection(keysDir);
        return services.BuildServiceProvider();
    }
}

