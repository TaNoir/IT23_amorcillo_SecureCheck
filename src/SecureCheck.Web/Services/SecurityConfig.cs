using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>
/// Login/password rules and authorization policies, kept in one place
/// so Program.cs and the unit tests use exactly the same settings.
/// </summary>
public static class SecurityConfig
{
    public static void ConfigureIdentity(IdentityOptions options)
    {
        options.SignIn.RequireConfirmedAccount = false;

        // Min 8 chars, needs digit + upper + lower.
        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = false;

        // Lock the account for 10 minutes after 5 failed logins.
        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

        options.User.RequireUniqueEmail = true;
    }

    public static void ConfigureAuthorization(AuthorizationOptions options)
    {
        // Every page requires login unless it is marked [AllowAnonymous].
        options.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();

        options.AddPolicy(AppPolicies.Manage, p => p
            .RequireAuthenticatedUser()
            .RequireRole(AppRoles.Administrator));

        options.AddPolicy(AppPolicies.Audit, p => p
            .RequireAuthenticatedUser()
            .RequireRole(AppRoles.Administrator, AppRoles.Auditor));
    }

    /// <summary>
    /// How often the login cookie is re-checked against the database.
    /// Deactivating a user or changing their role updates the security stamp,
    /// so their existing session ends within this interval (default would be 30 minutes).
    /// </summary>
    public static readonly TimeSpan SecurityStampValidationInterval = TimeSpan.FromMinutes(1);

    public static void ConfigureSecurityStamp(SecurityStampValidatorOptions options)
    {
        options.ValidationInterval = SecurityStampValidationInterval;
    }

    /// <summary>
    /// Data Protection for encrypted audit credentials.
    /// Keys are persisted so passwords still decrypt after a restart, and the key files
    /// themselves are encrypted with Windows DPAPI (otherwise they are written in plain text).
    /// </summary>
    public static IDataProtectionBuilder AddSecureCheckDataProtection(this IServiceCollection services, DirectoryInfo keysDirectory)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("SecureCheck runs on Windows only (DPAPI is used to protect encryption keys).");

        return services.AddDataProtection()
            .SetApplicationName("SecureCheck")
            .PersistKeysToFileSystem(keysDirectory)
            .ProtectKeysWithDpapi();
    }
}

