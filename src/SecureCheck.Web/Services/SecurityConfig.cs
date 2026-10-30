using Microsoft.AspNetCore.Authorization;
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
}

