using SecureCheck.Web.Services;

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

    public static string ToBadgeClass(this CheckStatus status) => status switch
    {
        CheckStatus.Pass => "risk-low",
        CheckStatus.Fail => "risk-critical",
        CheckStatus.Error => "status-error",
        CheckStatus.Skipped => "status-error",
        _ => "status-error"
    };

    public static string ToDisplayName(this AuditRunStatus status) => status switch
    {
        AuditRunStatus.CompletedWithErrors => "Completed with Errors",
        _ => status.ToString()
    };

    public static string ToBadgeClass(this AuditRunStatus status) => status switch
    {
        AuditRunStatus.Queued => "status-error",
        AuditRunStatus.Running => "sc-badge-navy",
        AuditRunStatus.Completed => "risk-low",
        AuditRunStatus.CompletedWithErrors => "risk-high",
        _ => "status-error"
    };

    public static string ToDisplayName(this ComputerAuditStatus status) => status.ToString();

    public static string ToBadgeClass(this ComputerAuditStatus status) => status switch
    {
        ComputerAuditStatus.Pending => "status-error",
        ComputerAuditStatus.Running => "sc-badge-navy",
        ComputerAuditStatus.Completed => "risk-low",
        ComputerAuditStatus.Unreachable => "status-error",
        ComputerAuditStatus.Failed => "risk-critical",
        _ => "status-error"
    };

    public static string ToDisplayName(this ExecutionMode mode) => mode switch
    {
        ExecutionMode.Local => "Local Machine",
        ExecutionMode.Demo => "Simulated Demo",
        ExecutionMode.Remote => "Remote WinRM",
        _ => mode.ToString()
    };

    public static string ToIconClass(this ExecutionMode mode) => mode switch
    {
        ExecutionMode.Local => "bi-laptop",
        ExecutionMode.Demo => "bi-cpu",
        ExecutionMode.Remote => "bi-hdd-network",
        _ => "bi-pc-display"
    };
}

