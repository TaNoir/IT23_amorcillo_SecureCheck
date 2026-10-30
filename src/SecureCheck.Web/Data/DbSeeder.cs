using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Data;

/// <summary>
/// Runs once at startup. Safe to run many times (idempotent):
/// applies migrations, creates the 3 roles, and creates the first admin if there are no users.
/// </summary>
public static class DbSeeder
{
    public static async Task SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var sp = scope.ServiceProvider;
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(DbSeeder));

        var db = sp.GetRequiredService<ApplicationDbContext>();
        await db.Database.MigrateAsync();

        var roleManager = sp.GetRequiredService<RoleManager<IdentityRole>>();
        await EnsureRolesAsync(roleManager, logger);

        var userManager = sp.GetRequiredService<UserManager<ApplicationUser>>();
        var options = sp.GetRequiredService<IOptions<SeedAdminOptions>>().Value;
        await EnsureAdminAsync(userManager, options, logger);
    }

    public static async Task EnsureRolesAsync(RoleManager<IdentityRole> roleManager, ILogger logger)
    {
        foreach (var role in AppRoles.All)
        {
            if (await roleManager.RoleExistsAsync(role))
                continue;

            var result = await roleManager.CreateAsync(new IdentityRole(role));
            if (!result.Succeeded)
                throw new InvalidOperationException($"Could not create role '{role}': {Describe(result)}");

            logger.LogInformation("Created role {Role}", role);
        }
    }

    public static async Task EnsureAdminAsync(UserManager<ApplicationUser> userManager, SeedAdminOptions options, ILogger logger)
    {
        // Only seed when the system has no users at all.
        if (await userManager.Users.AnyAsync())
            return;

        if (string.IsNullOrWhiteSpace(options.Email) || string.IsNullOrWhiteSpace(options.Password))
        {
            logger.LogWarning(
                "No users exist and SeedAdmin:Email / SeedAdmin:Password are not configured. " +
                "Set them (e.g. with dotnet user-secrets) and restart to create the first Administrator.");
            return;
        }

        var admin = new ApplicationUser
        {
            UserName = options.Email,
            Email = options.Email,
            EmailConfirmed = true,
            FullName = string.IsNullOrWhiteSpace(options.FullName) ? "System Administrator" : options.FullName,
            IsActive = true
        };

        var create = await userManager.CreateAsync(admin, options.Password);
        if (!create.Succeeded)
            throw new InvalidOperationException($"Could not create seed admin: {Describe(create)}");

        var addRole = await userManager.AddToRoleAsync(admin, AppRoles.Administrator);
        if (!addRole.Succeeded)
            throw new InvalidOperationException($"Could not assign Administrator role: {Describe(addRole)}");

        // Never log the password.
        logger.LogInformation("Created seed Administrator {Email}", options.Email);
    }

    private static string Describe(IdentityResult result) =>
        string.Join("; ", result.Errors.Select(e => e.Description));
}

