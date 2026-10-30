using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace SecureCheck.Web.Models;

/// <summary>
/// A SecureCheck user (Administrator, Auditor or Viewer).
/// </summary>
public class ApplicationUser : IdentityUser
{
    [Required, MaxLength(100)]
    public string FullName { get; set; } = string.Empty;

    /// <summary>Inactive users cannot log in.</summary>
    public bool IsActive { get; set; } = true;
}

