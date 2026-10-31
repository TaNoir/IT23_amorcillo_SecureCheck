using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// Audit trail of administrative and operational actions (never contains passwords).
/// </summary>
public class ActivityLog
{
    public int Id { get; set; }

    [Required, MaxLength(256)]
    public string UserName { get; set; } = string.Empty;

    [Required, MaxLength(100)]
    public string Action { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? Details { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

