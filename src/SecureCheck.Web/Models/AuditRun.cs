using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// A batch audit run started by an Administrator or Auditor across one or more computers.
/// </summary>
public class AuditRun
{
    public int Id { get; set; }

    [MaxLength(450)]
    public string? StartedByUserId { get; set; }

    [Required, MaxLength(150)]
    public string StartedByName { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? StartedAt { get; set; }

    public DateTime? FinishedAt { get; set; }

    public AuditRunStatus Status { get; set; } = AuditRunStatus.Queued;

    public int TotalComputers { get; set; }

    public int CompletedComputers { get; set; }

    public ICollection<ComputerAudit> ComputerAudits { get; set; } = new List<ComputerAudit>();
}

