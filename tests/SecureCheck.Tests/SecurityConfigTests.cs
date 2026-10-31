using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

public class SecurityConfigTests
{
    private static IAuthorizationService CreateAuthorizationService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(SecurityConfig.ConfigureAuthorization);
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    private static ClaimsPrincipal UserInRole(string? role)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, "test@securecheck.local") };
        if (role is not null)
            claims.Add(new Claim(ClaimTypes.Role, role));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Test"));
    }

    private static readonly ClaimsPrincipal Anonymous = new(new ClaimsIdentity());

    [Theory]
    [InlineData(AppRoles.Administrator, true, true)]
    [InlineData(AppRoles.Auditor, false, true)]
    [InlineData(AppRoles.Viewer, false, false)]
    [InlineData(null, false, false)]
    public async Task Policies_match_the_roles_table(string? role, bool canManage, bool canAudit)
    {
        var auth = CreateAuthorizationService();
        var user = UserInRole(role);

        Assert.Equal(canManage, (await auth.AuthorizeAsync(user, AppPolicies.Manage)).Succeeded);
        Assert.Equal(canAudit, (await auth.AuthorizeAsync(user, AppPolicies.Audit)).Succeeded);
    }

    [Fact]
    public async Task Anonymous_user_fails_every_policy()
    {
        var auth = CreateAuthorizationService();

        Assert.False((await auth.AuthorizeAsync(Anonymous, AppPolicies.Manage)).Succeeded);
        Assert.False((await auth.AuthorizeAsync(Anonymous, AppPolicies.Audit)).Succeeded);
    }

    [Fact]
    public async Task Fallback_policy_requires_a_logged_in_user()
    {
        var options = new AuthorizationOptions();
        SecurityConfig.ConfigureAuthorization(options);
        Assert.NotNull(options.FallbackPolicy);

        var auth = CreateAuthorizationService();
        Assert.False((await auth.AuthorizeAsync(Anonymous, options.FallbackPolicy!)).Succeeded);
        Assert.True((await auth.AuthorizeAsync(UserInRole(AppRoles.Viewer), options.FallbackPolicy!)).Succeeded);
    }

    [Fact]
    public void Identity_options_match_the_brief()
    {
        var options = new IdentityOptions();
        SecurityConfig.ConfigureIdentity(options);

        Assert.False(options.SignIn.RequireConfirmedAccount);
        Assert.Equal(8, options.Password.RequiredLength);
        Assert.True(options.Password.RequireDigit);
        Assert.True(options.Password.RequireUppercase);
        Assert.True(options.Password.RequireLowercase);
        Assert.Equal(5, options.Lockout.MaxFailedAccessAttempts);
        Assert.Equal(TimeSpan.FromMinutes(10), options.Lockout.DefaultLockoutTimeSpan);
        Assert.True(options.Lockout.AllowedForNewUsers);
    }

    [Fact]
    public void Security_stamp_is_revalidated_within_one_minute()
    {
        // Deactivated or demoted users must lose their session quickly (default is 30 minutes).
        var options = new SecurityStampValidatorOptions();
        SecurityConfig.ConfigureSecurityStamp(options);

        Assert.True(options.ValidationInterval <= TimeSpan.FromMinutes(1));
    }
}

