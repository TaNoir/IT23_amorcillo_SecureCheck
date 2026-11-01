using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Alerts;

/// <summary>
/// Open and Acknowledged risk alerts (/Alerts).
/// All authenticated roles can view alerts; Administrator and Auditor (AuditPolicy) can acknowledge alerts.
/// </summary>
public class IndexModel : PageModel
{
    public const int PageSize = 25;

    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;
    private readonly ActivityLogService _activityLog;

    public IndexModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService,
        ActivityLogService activityLog)
    {
        _db = db;
        _authorizationService = authorizationService;
        _activityLog = activityLog;
    }

    [BindProperty(SupportsGet = true)]
    public string Tab { get; set; } = "open";

    [BindProperty(SupportsGet = true)]
    public int PageNumber { get; set; } = 1;

    [TempData]
    public string? StatusMessage { get; set; }

    public bool CanAudit { get; private set; }
    public bool IsAcknowledgedTab => string.Equals(Tab, "acknowledged", StringComparison.OrdinalIgnoreCase);
    public int OpenCount { get; private set; }
    public int AcknowledgedCount { get; private set; }
    public int TotalPages { get; private set; } = 1;
    public IReadOnlyList<Alert> Alerts { get; private set; } = Array.Empty<Alert>();

    public async Task OnGetAsync()
    {
        var ct = HttpContext.RequestAborted;

        Tab = NormalizeTab(Tab);
        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;

        OpenCount = await _db.Alerts.AsNoTracking().CountAsync(a => !a.IsAcknowledged, ct);
        AcknowledgedCount = await _db.Alerts.AsNoTracking().CountAsync(a => a.IsAcknowledged, ct);

        var activeTabTotal = IsAcknowledgedTab ? AcknowledgedCount : OpenCount;
        TotalPages = Audits.IndexModel.CalculateTotalPages(activeTabTotal, PageSize);
        PageNumber = Math.Clamp(PageNumber, 1, TotalPages);

        var query = _db.Alerts
            .AsNoTracking()
            .Include(a => a.Computer)
            .Where(a => a.IsAcknowledged == IsAcknowledgedTab);

        query = IsAcknowledgedTab
            ? query.OrderByDescending(a => a.AcknowledgedAt ?? a.CreatedAt).ThenByDescending(a => a.Id)
            : query.OrderByDescending(a => a.CreatedAt).ThenByDescending(a => a.Id);

        Alerts = await query
            .Skip((PageNumber - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync(ct);
    }

    public async Task<IActionResult> OnPostAcknowledgeAsync(int id, string? tab = null)
    {
        if (!(await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded)
            return Forbid();

        var ct = HttpContext.RequestAborted;
        var alert = await _db.Alerts.FirstOrDefaultAsync(a => a.Id == id, ct);
        if (alert is null)
            return NotFound();

        var acknowledgerName = ResolveAcknowledgerName(User);
        if (TryAcknowledgeAlert(alert, acknowledgerName, DateTime.UtcNow))
        {
            await _db.SaveChangesAsync(ct);
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Acknowledged Alert",
                $"Alert #{alert.Id} — {alert.Message}");

            StatusMessage = "Alert acknowledged.";
        }
        else
        {
            StatusMessage = "Alert was already acknowledged.";
        }

        return RedirectToPage("./Index", new { Tab = NormalizeTab(tab) });
    }

    public async Task<IActionResult> OnPostAcknowledgeAllAsync()
    {
        if (!(await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded)
            return Forbid();

        var ct = HttpContext.RequestAborted;
        var openAlerts = await _db.Alerts
            .Where(a => !a.IsAcknowledged)
            .ToListAsync(ct);

        if (openAlerts.Count == 0)
        {
            StatusMessage = "There are no open alerts to acknowledge.";
            return RedirectToPage("./Index", new { Tab = "open" });
        }

        var acknowledgerName = ResolveAcknowledgerName(User);
        var nowUtc = DateTime.UtcNow;
        var count = 0;

        foreach (var alert in openAlerts)
        {
            if (TryAcknowledgeAlert(alert, acknowledgerName, nowUtc))
            {
                count++;
            }
        }

        if (count > 0)
        {
            await _db.SaveChangesAsync(ct);
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Acknowledged All Alerts",
                $"Acknowledged {count} open {(count == 1 ? "alert" : "alerts")}");
        }

        StatusMessage = $"Acknowledged {count} {(count == 1 ? "alert" : "alerts")}.";
        return RedirectToPage("./Index", new { Tab = "open" });
    }

    /// <summary>
    /// Marks an Alert acknowledged idempotently (preserving original AcknowledgedByName/AcknowledgedAt if already acknowledged).
    /// </summary>
    public static bool TryAcknowledgeAlert(Alert alert, string? acknowledgedByName, DateTime acknowledgedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(alert);

        if (alert.IsAcknowledged)
            return false;

        var cleanName = string.IsNullOrWhiteSpace(acknowledgedByName)
            ? "System"
            : acknowledgedByName.Trim();

        if (cleanName.Length > 150)
        {
            cleanName = cleanName[..150];
        }

        alert.IsAcknowledged = true;
        alert.AcknowledgedByName = cleanName;
        alert.AcknowledgedAt = acknowledgedAtUtc;
        return true;
    }

    public static string ResolveAcknowledgerName(ClaimsPrincipal user)
    {
        var fullName = user.GetFullName();
        if (!string.IsNullOrWhiteSpace(fullName))
            return fullName.Trim();

        return user.Identity?.Name ?? "System";
    }

    public static string NormalizeTab(string? tab) =>
        string.Equals(tab?.Trim(), "acknowledged", StringComparison.OrdinalIgnoreCase)
            ? "acknowledged"
            : "open";
}

