using Microsoft.AspNetCore.DataProtection;

namespace SecureCheck.Web.Services;

/// <summary>
/// Encrypts and decrypts audit credentials using ASP.NET Core Data Protection.
/// Plain-text passwords are never logged or stored directly in the database.
/// </summary>
public class CredentialProtector
{
    public const string Purpose = "SecureCheck.Credentials";

    private readonly IDataProtector _protector;

    public CredentialProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _protector = provider.CreateProtector(Purpose);
    }

    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        return _protector.Protect(plainText);
    }

    public string Unprotect(string protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        return _protector.Unprotect(protectedData);
    }
}

