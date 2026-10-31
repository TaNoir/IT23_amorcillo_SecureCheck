using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Computers;

[Authorize(Policy = AppPolicies.Manage)]
public class CreateModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly CredentialProtector _protector;
    private readonly ActivityLogService _activityLog;

    public CreateModel(
        ApplicationDbContext db,
        CredentialProtector protector,
        ActivityLogService activityLog)
    {
        _db = db;
        _protector = protector;
        _activityLog = activityLog;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        [Required, MaxLength(100)]
        [Display(Name = "Display Name")]
        public string Name { get; set; } = string.Empty;

        [Required, MaxLength(255)]
        [RegularExpression(PowerShellRunner.HostNameValidationPattern, ErrorMessage = PowerShellRunner.HostNameValidationMessage)]
        [Display(Name = "Host Name or IP Address")]
        public string HostName { get; set; } = string.Empty;

        [MaxLength(100)]
        [Display(Name = "Location")]
        public string? Location { get; set; }

        [MaxLength(500)]
        [Display(Name = "Description")]
        public string? Description { get; set; }

        [MaxLength(150)]
        [Display(Name = "Credential Username")]
        public string? CredentialUserName { get; set; }

        [DataType(DataType.Password), MaxLength(200)]
        [Display(Name = "Credential Password")]
        public string? CredentialPassword { get; set; }
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var name = Input.Name?.Trim() ?? string.Empty;
        var hostName = Input.HostName?.Trim() ?? string.Empty;
        var location = Input.Location?.Trim() ?? string.Empty;
        var description = string.IsNullOrWhiteSpace(Input.Description) ? null : Input.Description.Trim();
        var credUser = string.IsNullOrWhiteSpace(Input.CredentialUserName) ? null : Input.CredentialUserName.Trim();
        var credPass = Input.CredentialPassword;

        // Never echo a submitted password back to the page on validation errors.
        Input.CredentialPassword = null;

        if (!string.IsNullOrEmpty(name) &&
            await _db.Computers.AnyAsync(c => c.Name == name))
        {
            ModelState.AddModelError("Input.Name", "A computer with this display name already exists.");
        }

        if (credUser is not null && string.IsNullOrEmpty(credPass))
        {
            ModelState.AddModelError("Input.CredentialPassword", "Enter a password for the custom credential, or leave username blank to use the default credential.");
        }
        else if (credUser is null && !string.IsNullOrEmpty(credPass))
        {
            ModelState.AddModelError("Input.CredentialUserName", "Enter a username for the custom credential, or leave password blank to use the default credential.");
        }

        if (!ModelState.IsValid)
            return Page();

        var computer = new Computer
        {
            Name = name,
            HostName = hostName,
            Location = location,
            Description = description,
            IsActive = true,
            CredentialUserName = credUser,
            CredentialPasswordProtected = credUser is not null ? _protector.Protect(credPass!) : null,
            CreatedAt = DateTime.UtcNow
        };

        _db.Computers.Add(computer);
        await _db.SaveChangesAsync();

        var mode = PowerShellRunner.DetermineMode(computer.HostName);
        var credSummary = credUser is not null
            ? $"Custom ({credUser})"
            : mode == ExecutionMode.Local
                ? "Local machine (no credential needed)"
                : mode == ExecutionMode.Demo
                    ? "Simulated demo (no credential needed)"
                    : "Uses default credential";
        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Created Computer",
            $"{computer.Name} (Host: {computer.HostName}, Location: {(string.IsNullOrEmpty(computer.Location) ? "None" : computer.Location)}, Credential: {credSummary})");

        TempData["StatusMessage"] = $"Computer '{computer.Name}' added.";
        return RedirectToPage("./Index");
    }
}

