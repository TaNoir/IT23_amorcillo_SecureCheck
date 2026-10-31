using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// One of the 16 security checklist items evaluated during an audit.
/// </summary>
public class CheckDefinition
{
    public int Id { get; set; }

    [Required, MaxLength(40)]
    public string Code { get; set; } = string.Empty;

    [Required, MaxLength(150)]
    public string Name { get; set; } = string.Empty;

    public CheckCategory Category { get; set; }

    [MaxLength(500)]
    public string Description { get; set; } = string.Empty;

    public RiskLevel RiskLevel { get; set; }

    public int? Threshold { get; set; }

    [MaxLength(100)]
    public string? ThresholdLabel { get; set; }

    [Required, MaxLength(2000)]
    public string Remediation { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;

    public int SortOrder { get; set; }

    public ICollection<CheckResult> CheckResults { get; set; } = new List<CheckResult>();
}

