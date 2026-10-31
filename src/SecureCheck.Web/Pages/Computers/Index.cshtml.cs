using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Computers;

public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;
    private readonly ActivityLogService _activityLog;
    private readonly PowerShellRunner _runner;

    public IndexModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService,
        ActivityLogService activityLog,
        PowerShellRunner runner)
    {
        _db = db;
        _authorizationService = authorizationService;
        _activityLog = activityLog;
        _runner = runner;
    }

    [BindProperty(SupportsGet = true)]
    public string? Search { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Location { get; set; }

    [BindProperty(SupportsGet = true)]
    public string Status { get; set; } = "all";

    [TempData]
    public string? StatusMessage { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public bool CanManage { get; private set; }
    public bool CanAudit { get; private set; }
    public IReadOnlyList<string> Locations { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<Computer> Computers { get; private set; } = Array.Empty<Computer>();

    public async Task OnGetAsync()
    {
        CanManage = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Manage)).Succeeded;
        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;

        Locations = await _db.Computers
            .AsNoTracking()
            .Where(c => c.Location != "")
            .Select(c => c.Location)
            .Distinct()
            .OrderBy(l => l)
            .ToListAsync();

        var query = _db.Computers.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(Search))
        {
            var term = Search.Trim();
            query = query.Where(c =>
                c.Name.Contains(term) ||
                c.HostName.Contains(term) ||
                (c.Description != null && c.Description.Contains(term)));
        }

        if (!string.IsNullOrWhiteSpace(Location))
        {
            query = query.Where(c => c.Location == Location);
        }

        query = Status?.ToLowerInvariant() switch
        {
            "active" => query.Where(c => c.IsActive),
            "inactive" => query.Where(c => !c.IsActive),
            _ => query
        };

        Computers = await query
            .OrderByDescending(c => c.IsActive)
            .ThenBy(c => c.Name)
            .ToListAsync();
    }

    public async Task<IActionResult> OnPostTestConnectionAsync(
        int id,
        string? search,
        string? location,
        string? status)
    {
        if (!(await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded)
            return Forbid();

        var computer = await _db.Computers.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
        if (computer is null)
            return NotFound();

        var result = await _runner.RunTestAsync(
            computer,
            PowerShellRunner.DefaultTestTimeoutSeconds,
            HttpContext.RequestAborted);

        if (result.Success)
        {
            var connectedMessage = $"Connected to {result.ComputerName} (PowerShell {result.PowerShellVersion})";
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Tested Connection",
                $"{computer.Name} ({computer.HostName}): Succeeded — {connectedMessage}");
            StatusMessage = connectedMessage;
        }
        else
        {
            var friendlyError = result.ErrorMessage ?? "Connection test failed.";
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Tested Connection",
                $"{computer.Name} ({computer.HostName}): Failed ({result.ErrorKind}) — {friendlyError}");
            ErrorMessage = $"{computer.Name} ({computer.HostName}): {friendlyError}";
        }

        return RedirectToPage("./Index", new { Search = search, Location = location, Status = status ?? "all" });
    }

    public async Task<IActionResult> OnPostToggleActiveAsync(
        int id,
        string? search,
        string? location,
        string? status)
    {
        if (!(await _authorizationService.AuthorizeAsync(User, AppPolicies.Manage)).Succeeded)
            return Forbid();

        var computer = await _db.Computers.FindAsync(id);
        if (computer is null)
            return NotFound();

        computer.IsActive = !computer.IsActive;
        await _db.SaveChangesAsync();

        var action = computer.IsActive ? "Activated Computer" : "Deactivated Computer";
        await _activityLog.LogAsync(
            User.Identity?.Name,
            action,
            $"{computer.Name} ({computer.HostName})");

        StatusMessage = $"Computer '{computer.Name}' has been {(computer.IsActive ? "activated" : "deactivated")}.";
        return RedirectToPage("./Index", new { Search = search, Location = location, Status = status ?? "all" });
    }
}
