using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// High or Critical risk alert raised when a ComputerAudit completes with serious findings.
/// </summary>
public class Alert
{
    public int Id { get; set; }

    public int ComputerId { get; set; }
    public Computer Computer { get; set; } = null!;

    public int ComputerAuditId { get; set; }
    public ComputerAudit ComputerAudit { get; set; } = null!;

    public RiskLevel Severity { get; set; }

    [Required, MaxLength(500)]
    public string Message { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool IsAcknowledged { get; set; }

    [MaxLength(150)]
    public string? AcknowledgedByName { get; set; }

    public DateTime? AcknowledgedAt { get; set; }
}

