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
public class EditModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly CredentialProtector _protector;
    private readonly ActivityLogService _activityLog;

    public EditModel(
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

    public bool HasStoredCredential { get; private set; }

    public class InputModel
    {
        public int Id { get; set; }

        [Required, MaxLength(100)]
        [Display(Name = "Display Name")]
        public string Name { get; set; } = string.Empty;

        [Required, MaxLength(255)]
        [RegularExpression(@"^[A-Za-z0-9.-]+$", ErrorMessage = "Host name or IP may contain only letters, digits, dots, and hyphens.")]
        [Display(Name = "Host Name or IP Address")]
        public string HostName { get; set; } = string.Empty;

        [MaxLength(100)]
        [Display(Name = "Location")]
        public string? Location { get; set; }

        [MaxLength(500)]
        [Display(Name = "Description")]
        public string? Description { get; set; }

        [Display(Name = "Active")]
        public bool IsActive { get; set; } = true;

        [MaxLength(150)]
        [Display(Name = "Credential Username")]
        public string? CredentialUserName { get; set; }

        [DataType(DataType.Password), MaxLength(200)]
        [Display(Name = "Credential Password")]
        public string? CredentialPassword { get; set; }

        [Display(Name = "Clear custom credential and use default credential")]
        public bool ClearCredential { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(int id)
    {
        var computer = await _db.Computers.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
        if (computer is null)
            return NotFound();

        HasStoredCredential = !string.IsNullOrWhiteSpace(computer.CredentialUserName) &&
                              !string.IsNullOrEmpty(computer.CredentialPasswordProtected);

        Input = new InputModel
        {
            Id = computer.Id,
            Name = computer.Name,
            HostName = computer.HostName,
            Location = computer.Location,
            Description = computer.Description,
            IsActive = computer.IsActive,
            CredentialUserName = computer.CredentialUserName
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(int id)
    {
        var computer = await _db.Computers.FirstOrDefaultAsync(c => c.Id == id);
        if (computer is null)
            return NotFound();

        HasStoredCredential = !string.IsNullOrWhiteSpace(computer.CredentialUserName) &&
                              !string.IsNullOrEmpty(computer.CredentialPasswordProtected);

        var name = Input.Name?.Trim() ?? string.Empty;
        var hostName = Input.HostName?.Trim() ?? string.Empty;
        var location = Input.Location?.Trim() ?? string.Empty;
        var description = string.IsNullOrWhiteSpace(Input.Description) ? null : Input.Description.Trim();
        var credUser = string.IsNullOrWhiteSpace(Input.CredentialUserName) ? null : Input.CredentialUserName.Trim();
        var credPass = Input.CredentialPassword;

        // Never echo a submitted password back to the page.
        Input.CredentialPassword = null;

        if (!string.IsNullOrEmpty(name) &&
            await _db.Computers.AnyAsync(c => c.Id != computer.Id && c.Name == name))
        {
            ModelState.AddModelError("Input.Name", "Another computer with this display name already exists.");
        }

        if (!Input.ClearCredential)
        {
            if (credUser is null && !string.IsNullOrEmpty(credPass))
            {
                ModelState.AddModelError("Input.CredentialUserName", "Enter a username for the custom credential, or leave password blank to use the default credential.");
            }
            else if (credUser is not null && string.IsNullOrEmpty(credPass) && !HasStoredCredential)
            {
                ModelState.AddModelError("Input.CredentialPassword", "Enter a password when setting a custom credential for the first time.");
            }
        }

        if (!ModelState.IsValid)
            return Page();

        computer.Name = name;
        computer.HostName = hostName;
        computer.Location = location;
        computer.Description = description;
        computer.IsActive = Input.IsActive;

        string credChangeNote;
        if (Input.ClearCredential || credUser is null)
        {
            computer.CredentialUserName = null;
            computer.CredentialPasswordProtected = null;
            credChangeNote = "Uses default credential";
        }
        else if (!string.IsNullOrEmpty(credPass))
        {
            computer.CredentialUserName = credUser;
            computer.CredentialPasswordProtected = _protector.Protect(credPass);
            credChangeNote = $"Custom ({credUser}, password updated)";
        }
        else
        {
            computer.CredentialUserName = credUser;
            credChangeNote = $"Custom ({credUser}, password unchanged)";
        }

        await _db.SaveChangesAsync();

        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Updated Computer",
            $"{computer.Name} (Host: {computer.HostName}, Location: {(string.IsNullOrEmpty(computer.Location) ? "None" : computer.Location)}, Active: {computer.IsActive}, Credential: {credChangeNote})");

        TempData["StatusMessage"] = $"Computer '{computer.Name}' updated.";
        return RedirectToPage("./Index");
    }
}

