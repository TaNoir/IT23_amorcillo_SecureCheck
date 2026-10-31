using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Data;

/// <summary>
/// Runs once at startup. Safe to run many times (idempotent):
/// applies migrations, creates the 3 roles, creates the first admin if there are no users,
/// and seeds missing checklist definitions and default AppSettings without overwriting admin edits.
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

        await EnsureChecklistAsync(db, logger);
        await EnsureAppSettingsAsync(db, logger);
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

    public static async Task EnsureChecklistAsync(ApplicationDbContext db, ILogger logger)
    {
        var existingCodes = (await db.CheckDefinitions
                .Select(c => c.Code)
                .ToListAsync())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var added = 0;
        foreach (var seedCheck in GetDefaultChecks())
        {
            if (existingCodes.Contains(seedCheck.Code))
                continue;

            db.CheckDefinitions.Add(seedCheck);
            added++;
        }

        if (added > 0)
        {
            await db.SaveChangesAsync();
            logger.LogInformation("Seeded {Count} security check definitions", added);
        }
    }

    public static async Task EnsureAppSettingsAsync(ApplicationDbContext db, ILogger logger)
    {
        var existingKeys = (await db.AppSettings
                .Select(s => s.Key)
                .ToListAsync())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var added = 0;
        foreach (var setting in GetDefaultSettings())
        {
            if (existingKeys.Contains(setting.Key))
                continue;

            db.AppSettings.Add(setting);
            added++;
        }

        if (added > 0)
        {
            await db.SaveChangesAsync();
            logger.LogInformation("Seeded {Count} default application settings", added);
        }
    }

    public static IReadOnlyList<CheckDefinition> GetDefaultChecks() => new List<CheckDefinition>
    {
        new()
        {
            Code = "FW-DOMAIN",
            Name = "Firewall on (Domain profile)",
            Category = CheckCategory.Firewall,
            Description = "Domain profile enabled",
            RiskLevel = RiskLevel.High,
            Remediation = "Open Windows Security > Firewall & network protection and turn on the Domain network firewall. Or run as admin: `Set-NetFirewallProfile -Profile Domain -Enabled True`",
            IsEnabled = true,
            SortOrder = 1
        },
        new()
        {
            Code = "FW-PRIVATE",
            Name = "Firewall on (Private profile)",
            Category = CheckCategory.Firewall,
            Description = "Private profile enabled",
            RiskLevel = RiskLevel.High,
            Remediation = "Turn on the Private network firewall in Windows Security. Or run: `Set-NetFirewallProfile -Profile Private -Enabled True`",
            IsEnabled = true,
            SortOrder = 2
        },
        new()
        {
            Code = "FW-PUBLIC",
            Name = "Firewall on (Public profile)",
            Category = CheckCategory.Firewall,
            Description = "Public profile enabled",
            RiskLevel = RiskLevel.Critical,
            Remediation = "Turn on the Public network firewall in Windows Security. Or run: `Set-NetFirewallProfile -Profile Public -Enabled True`",
            IsEnabled = true,
            SortOrder = 3
        },
        new()
        {
            Code = "UPD-RECENT",
            Name = "Recent Windows update installed",
            Category = CheckCategory.Updates,
            Description = "Days since last installed update ≤ threshold",
            RiskLevel = RiskLevel.High,
            Threshold = 30,
            ThresholdLabel = "Max days since last update",
            Remediation = "Go to Settings > Windows Update > Check for updates, install all updates, then restart the computer.",
            IsEnabled = true,
            SortOrder = 4
        },
        new()
        {
            Code = "AV-ENABLED",
            Name = "Antivirus turned on",
            Category = CheckCategory.Antivirus,
            Description = "AntivirusEnabled is true",
            RiskLevel = RiskLevel.Critical,
            Remediation = "Open Windows Security > Virus & threat protection and turn it on. If another antivirus is installed, make sure it is active and up to date.",
            IsEnabled = true,
            SortOrder = 5
        },
        new()
        {
            Code = "AV-REALTIME",
            Name = "Real-time protection on",
            Category = CheckCategory.Antivirus,
            Description = "RealTimeProtectionEnabled is true",
            RiskLevel = RiskLevel.High,
            Remediation = "Windows Security > Virus & threat protection > Manage settings > turn on Real-time protection. Or run: `Set-MpPreference -DisableRealtimeMonitoring $false`",
            IsEnabled = true,
            SortOrder = 6
        },
        new()
        {
            Code = "AV-SIGNATURES",
            Name = "Virus definitions up to date",
            Category = CheckCategory.Antivirus,
            Description = "Signature age ≤ threshold",
            RiskLevel = RiskLevel.Medium,
            Threshold = 7,
            ThresholdLabel = "Max days old",
            Remediation = "Windows Security > Virus & threat protection > Check for updates. Or run: `Update-MpSignature`",
            IsEnabled = true,
            SortOrder = 7
        },
        new()
        {
            Code = "ACC-GUEST",
            Name = "Guest account disabled",
            Category = CheckCategory.Accounts,
            Description = "Guest account (SID ending -501) disabled or missing",
            RiskLevel = RiskLevel.High,
            Remediation = "Run as admin: `Get-LocalUser | Where-Object SID -like '*-501' | Disable-LocalUser`",
            IsEnabled = true,
            SortOrder = 8
        },
        new()
        {
            Code = "ACC-ADMINS",
            Name = "Limited number of admin accounts",
            Category = CheckCategory.Accounts,
            Description = "Members of local Administrators ≤ threshold",
            RiskLevel = RiskLevel.Medium,
            Threshold = 2,
            ThresholdLabel = "Max admins",
            Remediation = "Open `lusrmgr.msc` > Groups > Administrators and remove accounts that do not need admin rights. Or run: `Remove-LocalGroupMember -Group Administrators -Member <name>`",
            IsEnabled = true,
            SortOrder = 9
        },
        new()
        {
            Code = "ACC-PWLENGTH",
            Name = "Minimum password length set",
            Category = CheckCategory.Accounts,
            Description = "Minimum password length ≥ threshold",
            RiskLevel = RiskLevel.Medium,
            Threshold = 8,
            ThresholdLabel = "Min characters",
            Remediation = "Open `secpol.msc` > Account Policies > Password Policy > Minimum password length = 8 or more. Or run: `net accounts /minpwlen:8`. In a domain, set it in Group Policy.",
            IsEnabled = true,
            SortOrder = 10
        },
        new()
        {
            Code = "ACC-PWCOMPLEX",
            Name = "Password complexity turned on",
            Category = CheckCategory.Accounts,
            Description = "PasswordComplexity = 1",
            RiskLevel = RiskLevel.Medium,
            Remediation = "Open `secpol.msc` > Account Policies > Password Policy > enable \"Password must meet complexity requirements\". In a domain, set it in Group Policy.",
            IsEnabled = true,
            SortOrder = 11
        },
        new()
        {
            Code = "ACC-LOCKOUT",
            Name = "Account lockout turned on",
            Category = CheckCategory.Accounts,
            Description = "Lockout threshold is between 1 and the threshold",
            RiskLevel = RiskLevel.Medium,
            Threshold = 10,
            ThresholdLabel = "Max failed attempts",
            Remediation = "Open `secpol.msc` > Account Policies > Account Lockout Policy > set threshold to 5. Or run: `net accounts /lockoutthreshold:5`",
            IsEnabled = true,
            SortOrder = 12
        },
        new()
        {
            Code = "SVC-REMOTEREG",
            Name = "Remote Registry service off",
            Category = CheckCategory.ServicesAndFeatures,
            Description = "Service not running and not set to Automatic",
            RiskLevel = RiskLevel.Medium,
            Remediation = "Run as admin: `Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled`",
            IsEnabled = true,
            SortOrder = 13
        },
        new()
        {
            Code = "SVC-RDP",
            Name = "Remote Desktop turned off",
            Category = CheckCategory.ServicesAndFeatures,
            Description = "fDenyTSConnections = 1",
            RiskLevel = RiskLevel.Medium,
            Remediation = "Settings > System > Remote Desktop > Off. If Remote Desktop is really needed, allow only specific users and keep Network Level Authentication on.",
            IsEnabled = true,
            SortOrder = 14
        },
        new()
        {
            Code = "SVC-SMB1",
            Name = "SMBv1 protocol turned off",
            Category = CheckCategory.ServicesAndFeatures,
            Description = "SMB1 server protocol disabled and SMB1Protocol feature not Enabled",
            RiskLevel = RiskLevel.Critical,
            Remediation = "Run as admin: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` and `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`, then restart.",
            IsEnabled = true,
            SortOrder = 15
        },
        new()
        {
            Code = "SVC-TELNET",
            Name = "Telnet Client feature turned off",
            Category = CheckCategory.ServicesAndFeatures,
            Description = "TelnetClient feature not Enabled",
            RiskLevel = RiskLevel.Low,
            Remediation = "Run as admin: `Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart`",
            IsEnabled = true,
            SortOrder = 16
        }
    };

    public static IReadOnlyList<AppSetting> GetDefaultSettings() => new List<AppSetting>
    {
        new() { Key = AppSettingKeys.DefaultCredentialUserName, Value = string.Empty },
        new() { Key = AppSettingKeys.DefaultCredentialPasswordProtected, Value = string.Empty },
        new() { Key = AppSettingKeys.MaxParallelAudits, Value = "5" },
        new() { Key = AppSettingKeys.AuditTimeoutSeconds, Value = "180" },
        new() { Key = AppSettingKeys.ScoreGoodMin, Value = "90" },
        new() { Key = AppSettingKeys.ScoreFairMin, Value = "70" },
        new() { Key = AppSettingKeys.ScorePoorMin, Value = "50" }
    };

    private static string Describe(IdentityResult result) =>
        string.Join("; ", result.Errors.Select(e => e.Description));
}
