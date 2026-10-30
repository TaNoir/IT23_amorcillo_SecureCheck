namespace SecureCheck.Web.Models;

/// <summary>Role names used by ASP.NET Core Identity.</summary>
public static class AppRoles
{
    public const string Administrator = "Administrator";
    public const string Auditor = "Auditor";
    public const string Viewer = "Viewer";

    public static readonly string[] All = { Administrator, Auditor, Viewer };
}

/// <summary>Authorization policy names (see PROJECT_BRIEF "User roles").</summary>
public static class AppPolicies
{
    /// <summary>Administrator only.</summary>
    public const string Manage = "ManagePolicy";

    /// <summary>Administrator or Auditor.</summary>
    public const string Audit = "AuditPolicy";
}

/// <summary>Custom claim types added to the login cookie.</summary>
public static class AppClaimTypes
{
    public const string FullName = "securecheck:fullname";
}

