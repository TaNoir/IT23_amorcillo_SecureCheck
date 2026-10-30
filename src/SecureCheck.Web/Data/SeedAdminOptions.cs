namespace SecureCheck.Web.Data;

/// <summary>
/// Bound from the "SeedAdmin" configuration section.
/// Keep the password out of source control: set it with
/// <c>dotnet user-secrets set "SeedAdmin:Password" "..."</c> or an environment variable
/// (<c>SeedAdmin__Password</c>).
/// </summary>
public class SeedAdminOptions
{
    public const string SectionName = "SeedAdmin";

    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FullName { get; set; } = "System Administrator";
}

