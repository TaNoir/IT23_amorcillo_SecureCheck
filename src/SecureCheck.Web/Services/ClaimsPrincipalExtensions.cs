using System.Security.Claims;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

public static class ClaimsPrincipalExtensions
{
    /// <summary>Returns the FullName claim, falling back to the user name.</summary>
    public static string GetFullName(this ClaimsPrincipal user)
    {
        var fullName = user.FindFirstValue(AppClaimTypes.FullName);
        if (!string.IsNullOrWhiteSpace(fullName))
            return fullName;

        return user.Identity?.Name ?? string.Empty;
    }
}

