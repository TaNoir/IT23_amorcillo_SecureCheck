using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Admin.Users;

[Authorize(Policy = AppPolicies.Manage)]
public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ActivityLogService _activityLog;

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        ActivityLogService activityLog)
    {
        _userManager = userManager;
        _activityLog = activityLog;
    }

    public CreateUserInput Create { get; set; } = new();

    public IReadOnlyList<UserRow> Users { get; private set; } = Array.Empty<UserRow>();
    public string CurrentUserId { get; private set; } = string.Empty;

    [TempData]
    public string? StatusMessage { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public record UserRow(
        string Id,
        string FullName,
        string Email,
        string Role,
        bool IsActive,
        bool IsLockedOut);

    public class CreateUserInput
    {
        [Required, MaxLength(100)]
        [Display(Name = "Full Name")]
        public string FullName { get; set; } = string.Empty;

        [Required, EmailAddress, MaxLength(256)]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Role")]
        public string Role { get; set; } = AppRoles.Auditor;

        [Required, DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Temporary password must be at least {2} characters.")]
        [Display(Name = "Temporary Password")]
        public string TempPassword { get; set; } = string.Empty;
    }

    public async Task OnGetAsync()
    {
        await LoadUsersAsync();
    }

    public async Task<IActionResult> OnPostCreateAsync([Bind(Prefix = "Create")] CreateUserInput input)
    {
        var tempPassword = input.TempPassword;
        // Never echo a submitted password back into the HTML form.
        input.TempPassword = string.Empty;
        Create = input;

        var email = input.Email?.Trim() ?? string.Empty;
        var fullName = input.FullName?.Trim() ?? string.Empty;

        if (!AppRoles.All.Contains(input.Role))
        {
            ModelState.AddModelError("Create.Role", "Select a valid role.");
        }

        if (!string.IsNullOrEmpty(email) && await _userManager.FindByEmailAsync(email) is not null)
        {
            ModelState.AddModelError("Create.Email", "A user with this email address already exists.");
        }

        if (!ModelState.IsValid)
        {
            await LoadUsersAsync();
            return Page();
        }

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            FullName = fullName,
            IsActive = true
        };

        var createResult = await _userManager.CreateAsync(user, tempPassword);
        if (!createResult.Succeeded)
        {
            foreach (var err in createResult.Errors)
                ModelState.AddModelError(string.Empty, err.Description);

            await LoadUsersAsync();
            return Page();
        }

        var roleResult = await _userManager.AddToRoleAsync(user, input.Role);
        if (!roleResult.Succeeded)
        {
            foreach (var err in roleResult.Errors)
                ModelState.AddModelError(string.Empty, err.Description);

            await LoadUsersAsync();
            return Page();
        }

        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Created User",
            $"{user.FullName} ({user.Email}) with role {input.Role}");

        StatusMessage = $"Created user '{user.FullName}' ({user.Email}) as {input.Role}.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostChangeRoleAsync(string userId, string role)
    {
        if (!AppRoles.All.Contains(role))
        {
            ErrorMessage = "Invalid role selected.";
            return RedirectToPage();
        }

        var currentUserId = _userManager.GetUserId(User);
        if (userId == currentUserId && role != AppRoles.Administrator)
        {
            ErrorMessage = "You cannot remove the Administrator role from your own account.";
            return RedirectToPage();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return NotFound();

        var currentRoles = await _userManager.GetRolesAsync(user);
        var previousRole = currentRoles.FirstOrDefault() ?? "None";
        if (currentRoles.Count == 1 && currentRoles[0] == role)
        {
            StatusMessage = $"'{user.FullName}' is already assigned the {role} role.";
            return RedirectToPage();
        }

        if (currentRoles.Count > 0)
        {
            var remove = await _userManager.RemoveFromRolesAsync(user, currentRoles);
            if (!remove.Succeeded)
            {
                ErrorMessage = Describe(remove);
                return RedirectToPage();
            }
        }

        var add = await _userManager.AddToRoleAsync(user, role);
        if (!add.Succeeded)
        {
            ErrorMessage = Describe(add);
            return RedirectToPage();
        }

        await _userManager.UpdateSecurityStampAsync(user);

        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Changed User Role",
            $"{user.FullName} ({user.Email}): {previousRole} -> {role}");

        StatusMessage = $"Updated role for '{user.FullName}' to {role}.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostResetPasswordAsync(string userId, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            ErrorMessage = "Enter a new password to reset the account.";
            return RedirectToPage();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return NotFound();

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var reset = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!reset.Succeeded)
        {
            ErrorMessage = $"Could not reset password for '{user.Email}': {Describe(reset)}";
            return RedirectToPage();
        }

        // Clear temporary failed-attempt lockouts if the user is active.
        if (user.IsActive)
        {
            await _userManager.SetLockoutEndDateAsync(user, null);
            await _userManager.ResetAccessFailedCountAsync(user);
        }

        await _userManager.UpdateSecurityStampAsync(user);

        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Reset User Password",
            $"Password reset for {user.FullName} ({user.Email})");

        StatusMessage = $"Password has been reset for '{user.FullName}' ({user.Email}).";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostDeactivateAsync(string userId)
    {
        var currentUserId = _userManager.GetUserId(User);
        if (userId == currentUserId)
        {
            ErrorMessage = "You cannot deactivate your own account.";
            return RedirectToPage();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return NotFound();

        user.IsActive = false;
        await _userManager.UpdateAsync(user);
        await _userManager.SetLockoutEnabledAsync(user, true);
        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
        await _userManager.UpdateSecurityStampAsync(user);

        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Deactivated User",
            $"{user.FullName} ({user.Email})");

        StatusMessage = $"Deactivated user '{user.FullName}' ({user.Email}).";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostActivateAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return NotFound();

        user.IsActive = true;
        await _userManager.UpdateAsync(user);
        await _userManager.SetLockoutEndDateAsync(user, null);
        await _userManager.ResetAccessFailedCountAsync(user);
        await _userManager.UpdateSecurityStampAsync(user);

        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Activated User",
            $"{user.FullName} ({user.Email})");

        StatusMessage = $"Activated user '{user.FullName}' ({user.Email}).";
        return RedirectToPage();
    }

    private async Task LoadUsersAsync()
    {
        CurrentUserId = _userManager.GetUserId(User) ?? string.Empty;

        var allUsers = await _userManager.Users
            .OrderByDescending(u => u.IsActive)
            .ThenBy(u => u.FullName)
            .ToListAsync();

        var rows = new List<UserRow>(allUsers.Count);
        var now = DateTimeOffset.UtcNow;

        foreach (var u in allUsers)
        {
            var roles = await _userManager.GetRolesAsync(u);
            var role = roles.FirstOrDefault() ?? AppRoles.Viewer;
            var lockedOut = u.LockoutEnabled && u.LockoutEnd.HasValue && u.LockoutEnd.Value > now;
            rows.Add(new UserRow(u.Id, u.FullName, u.Email ?? u.UserName ?? string.Empty, role, u.IsActive, lockedOut));
        }

        Users = rows;
    }

    private static string Describe(IdentityResult result) =>
        string.Join(" ", result.Errors.Select(e => e.Description));
}

