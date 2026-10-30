using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages;

/// <summary>Dashboard placeholder (full dashboard comes in Phase 7).</summary>
public class IndexModel : PageModel
{
    public string FullName { get; private set; } = string.Empty;
    public string RoleNames { get; private set; } = string.Empty;

    public void OnGet()
    {
        FullName = User.GetFullName();
        var roles = AppRoles.All.Where(User.IsInRole).ToList();
        RoleNames = roles.Count > 0 ? string.Join(", ", roles) : "No role";
    }
}

