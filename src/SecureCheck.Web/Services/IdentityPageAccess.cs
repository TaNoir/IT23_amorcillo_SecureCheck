using Microsoft.AspNetCore.Http;

namespace SecureCheck.Web.Services;

/// <summary>
/// The Identity UI package ships many pages (Register, ForgotPassword, 2FA, ...).
/// SecureCheck only uses a few of them, so every other /Identity URL returns 404.
/// This is how the public Register page is removed.
/// </summary>
public static class IdentityPageAccess
{
    private static readonly PathString IdentityRoot = new("/Identity");

    private static readonly HashSet<string> AllowedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/Identity/Account/Login",
        "/Identity/Account/Logout",
        "/Identity/Account/AccessDenied",
        "/Identity/Account/Manage/ChangePassword"
    };

    /// <summary>True if the request should be blocked with 404.</summary>
    public static bool IsBlocked(PathString path)
    {
        if (!path.StartsWithSegments(IdentityRoot))
            return false;

        var value = path.Value!.TrimEnd('/');
        return !AllowedPaths.Contains(value);
    }

    /// <summary>Middleware: blocks Identity pages that SecureCheck does not use.</summary>
    public static IApplicationBuilder UseIdentityPageAllowList(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            if (IsBlocked(context.Request.Path))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            await next();
        });
}

