using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// Result of evaluating one CheckDefinition on one ComputerAudit.
/// Stores snapshot copies of Code, Name, Category, RiskLevel, and Remediation so later
/// checklist edits never alter historical audit results.
/// </summary>
public class CheckResult
{
    public int Id { get; set; }

    public int ComputerAuditId { get; set; }
    public ComputerAudit ComputerAudit { get; set; } = null!;

    public int CheckDefinitionId { get; set; }
    public CheckDefinition CheckDefinition { get; set; } = null!;

    [Required, MaxLength(40)]
    public string Code { get; set; } = string.Empty;

    [Required, MaxLength(150)]
    public string Name { get; set; } = string.Empty;

    public CheckCategory Category { get; set; }

    public RiskLevel RiskLevel { get; set; }

    [MaxLength(2000)]
    public string Remediation { get; set; } = string.Empty;

    public CheckStatus Status { get; set; }

    [MaxLength(500)]
    public string? ActualValue { get; set; }

    [MaxLength(500)]
    public string? ExpectedValue { get; set; }

    [MaxLength(1000)]
    public string? Message { get; set; }
}

