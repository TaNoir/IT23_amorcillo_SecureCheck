using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Areas.Identity.Pages.Account;

[AllowAnonymous]
public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<LogoutModel> _logger;

    public LogoutModel(SignInManager<ApplicationUser> signInManager, ILogger<LogoutModel> logger)
    {
        _signInManager = signInManager;
        _logger = logger;
    }

    public void OnGet()
    {
    }

    // POST only (with anti-forgery token) so a link/image can't log people out.
    public async Task<IActionResult> OnPostAsync()
    {
        var name = User.Identity?.Name;
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User {Name} logged out", name);
        return RedirectToPage("./Login");
    }
}

