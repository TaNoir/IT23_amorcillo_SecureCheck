using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// The audit outcome for a single computer within an AuditRun.
/// </summary>
public class ComputerAudit
{
    public int Id { get; set; }

    public int AuditRunId { get; set; }
    public AuditRun AuditRun { get; set; } = null!;

    public int ComputerId { get; set; }
    public Computer Computer { get; set; } = null!;

    public ComputerAuditStatus Status { get; set; } = ComputerAuditStatus.Pending;

    public DateTime? StartedAt { get; set; }

    public DateTime? FinishedAt { get; set; }

    public int? Score { get; set; }

    public RiskLevel? OverallRisk { get; set; }

    public int PassedCount { get; set; }

    public int FailedCount { get; set; }

    public int ErrorCount { get; set; }

    [MaxLength(1000)]
    public string? ErrorMessage { get; set; }

    [MaxLength(200)]
    public string? OsCaption { get; set; }

    [MaxLength(100)]
    public string? OsVersion { get; set; }

    [MaxLength(50)]
    public string? PsVersion { get; set; }

    /// <summary>Raw JSON payload collected from the target computer (nvarchar(max)).</summary>
    public string? RawJson { get; set; }

    public ICollection<CheckResult> CheckResults { get; set; } = new List<CheckResult>();

    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}

