using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Areas.Identity.Pages.Account;

[AllowAnonymous]
public class LoginModel : PageModel
{
    // Same message for "no such user" and "wrong password" so we don't reveal which accounts exist.
    internal const string InvalidLoginMessage = "Invalid email or password.";
    internal const string InactiveMessage = "This account has been deactivated. Contact a System Administrator.";
    internal const string LockedOutMessage = "This account is locked after too many failed attempts. Try again in 10 minutes.";

    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<LoginModel> _logger;

    public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }

    public class InputModel
    {
        [Required, EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required, DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me")]
        public bool RememberMe { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
            return LocalRedirect(SafeReturnUrl(returnUrl));

        // Clear any old external cookie to ensure a clean login.
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;
        if (!ModelState.IsValid)
            return Page();

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, InvalidLoginMessage);
            return Page();
        }

        if (!user.IsActive)
        {
            _logger.LogWarning("Login blocked for inactive user {Email}", Input.Email);
            ModelState.AddModelError(string.Empty, InactiveMessage);
            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(user, Input.Password, Input.RememberMe, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} logged in", Input.Email);
            return LocalRedirect(SafeReturnUrl(returnUrl));
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User {Email} is locked out", Input.Email);
            ModelState.AddModelError(string.Empty, LockedOutMessage);
            return Page();
        }

        ModelState.AddModelError(string.Empty, InvalidLoginMessage);
        return Page();
    }

    /// <summary>Only allow redirects back into this site (prevents open redirects).</summary>
    private string SafeReturnUrl(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : Url.Content("~/");
}

