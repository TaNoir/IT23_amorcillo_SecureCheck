namespace SecureCheck.Web.Models;

public enum CheckCategory
{
    Firewall,
    Updates,
    Antivirus,
    Accounts,
    ServicesAndFeatures
}

public enum RiskLevel
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum AuditRunStatus
{
    Queued,
    Running,
    Completed,
    CompletedWithErrors
}

public enum ComputerAuditStatus
{
    Pending,
    Running,
    Completed,
    Unreachable,
    Failed
}

public enum CheckStatus
{
    Pass,
    Fail,
    Error,
    Skipped
}

public static class EnumDisplayExtensions
{
    public static string ToDisplayName(this CheckCategory category) => category switch
    {
        CheckCategory.ServicesAndFeatures => "Services & Features",
        _ => category.ToString()
    };

    public static string ToBadgeClass(this RiskLevel risk) => risk switch
    {
        RiskLevel.Low => "risk-low",
        RiskLevel.Medium => "risk-medium",
        RiskLevel.High => "risk-high",
        RiskLevel.Critical => "risk-critical",
        _ => "status-error"
    };
}

