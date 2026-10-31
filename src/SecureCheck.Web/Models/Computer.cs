using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// A Windows computer (lab or office PC) managed and audited by SecureCheck.
/// </summary>
public class Computer
{
    public int Id { get; set; }

    [Required, MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [Required, MaxLength(255)]
    public string HostName { get; set; } = string.Empty;

    [MaxLength(100)]
    public string Location { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Description { get; set; }

    public bool IsActive { get; set; } = true;

    [MaxLength(150)]
    public string? CredentialUserName { get; set; }

    /// <summary>Encrypted with ASP.NET Core Data Protection via CredentialProtector.</summary>
    [MaxLength(2000)]
    public string? CredentialPasswordProtected { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastAuditedAt { get; set; }

    public int? LastScore { get; set; }

    public RiskLevel? LastRiskLevel { get; set; }

    public ICollection<ComputerAudit> ComputerAudits { get; set; } = new List<ComputerAudit>();

    public ICollection<Alert> Alerts { get; set; } = new List<Alert>();
}

