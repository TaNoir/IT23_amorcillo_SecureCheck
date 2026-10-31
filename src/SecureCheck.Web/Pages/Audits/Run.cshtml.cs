using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Audits;

[Authorize(Policy = AppPolicies.Audit)]
public class RunModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly AuditQueue _queue;
    private readonly ActivityLogService _activityLog;

    public RunModel(
        ApplicationDbContext db,
        AuditQueue queue,
        ActivityLogService activityLog)
    {
        _db = db;
        _queue = queue;
        _activityLog = activityLog;
    }

    [BindProperty(SupportsGet = true)]
    public string? Location { get; set; }

    [BindProperty]
    public List<int> SelectedComputerIds { get; set; } = new();

    public string? ErrorMessage { get; private set; }
    public IReadOnlyList<string> Locations { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<Computer> Computers { get; private set; } = Array.Empty<Computer>();
    public IReadOnlySet<int> BusyComputerIds { get; private set; } = new HashSet<int>();
    public int ScoreGoodMin { get; private set; } = 90;
    public int ScoreFairMin { get; private set; } = 70;
    public int ScorePoorMin { get; private set; } = 50;

    public async Task OnGetAsync(int? computerId = null)
    {
        if (computerId.HasValue && computerId.Value > 0 && SelectedComputerIds.Count == 0)
        {
            SelectedComputerIds.Add(computerId.Value);
        }

        await LoadPageDataAsync(HttpContext.RequestAborted);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var ct = HttpContext.RequestAborted;
        var distinctIds = (SelectedComputerIds ?? new List<int>())
            .Where(id => id > 0)
            .Distinct()
            .ToList();
        SelectedComputerIds = distinctIds;

        if (distinctIds.Count == 0)
        {
            ErrorMessage = "Please select at least one computer to start an audit.";
            ModelState.AddModelError(string.Empty, ErrorMessage);
            await LoadPageDataAsync(ct);
            return Page();
        }

        var selectedComputers = await _db.Computers
            .AsNoTracking()
            .Where(c => c.IsActive && distinctIds.Contains(c.Id))
            .OrderBy(c => c.Name)
            .ToListAsync(ct);

        if (selectedComputers.Count == 0)
        {
            ErrorMessage = "None of the selected computers are currently active.";
            ModelState.AddModelError(string.Empty, ErrorMessage);
            await LoadPageDataAsync(ct);
            return Page();
        }

        // Prevent auditing the same computer twice concurrently.
        var busyIds = await GetBusyComputerIdsQuery(_db.ComputerAudits.AsNoTracking(), distinctIds)
            .ToListAsync(ct);
        var busySet = busyIds.ToHashSet();

        var (eligible, skipped) = PartitionSelectedComputers(selectedComputers, busySet);

        if (eligible.Count == 0)
        {
            var skippedNames = string.Join(", ", skipped.Select(c => c.Name));
            ErrorMessage =
                $"All selected computers already have an audit in progress ({skippedNames}). Please wait for the active audit to finish.";
            ModelState.AddModelError(string.Empty, ErrorMessage);
            await LoadPageDataAsync(ct);
            return Page();
        }

        if (skipped.Count > 0)
        {
            var skippedNames = string.Join(", ", skipped.Select(c => c.Name));
            TempData["SkippedMessage"] =
                $"Skipped {skipped.Count} {(skipped.Count == 1 ? "computer" : "computers")} already being audited: {skippedNames}.";
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var startedByName = User.GetFullName();
        if (string.IsNullOrWhiteSpace(startedByName))
        {
            startedByName = User.Identity?.Name ?? "System";
        }

        var run = new AuditRun
        {
            StartedByUserId = userId,
            StartedByName = startedByName.Length <= 150 ? startedByName : startedByName[..150],
            CreatedAt = DateTime.UtcNow,
            Status = AuditRunStatus.Queued,
            TotalComputers = eligible.Count,
            CompletedComputers = 0,
            ComputerAudits = eligible
                .Select(c => new ComputerAudit
                {
                    ComputerId = c.Id,
                    Status = ComputerAuditStatus.Pending
                })
                .ToList()
        };

        _db.AuditRuns.Add(run);
        await _db.SaveChangesAsync(ct);

        var targetSummary = string.Join(", ", eligible.Select(c => $"{c.Name} ({c.HostName})"));
        if (targetSummary.Length > 1000)
        {
            targetSummary = targetSummary[..997] + "...";
        }

        await _activityLog.LogAsync(
            User.Identity?.Name,
            FormatActivityLogAction(run.Id, eligible.Count),
            targetSummary);

        await _queue.EnqueueAsync(run.Id, ct);

        return RedirectToPage("./Progress", new { runId = run.Id });
    }

    public (string Label, string BadgeClass, string TextClass) DescribeScore(int? score) =>
        AuditEvaluator.DescribeScore(score, ScoreGoodMin, ScoreFairMin, ScorePoorMin);

    /// <summary>
    /// Returns true if a ComputerAudit status means an audit is queued or actively running on that computer.
    /// </summary>
    public static bool IsBusyStatus(ComputerAuditStatus status) =>
        status is ComputerAuditStatus.Pending or ComputerAuditStatus.Running;

    /// <summary>
    /// Builds the EF Core query returning distinct ComputerIds that currently have a Pending or Running ComputerAudit.
    /// </summary>
    public static IQueryable<int> GetBusyComputerIdsQuery(
        IQueryable<ComputerAudit> query,
        IReadOnlyCollection<int>? candidateComputerIds = null)
    {
        ArgumentNullException.ThrowIfNull(query);

        var busyQuery = query.Where(ca =>
            ca.Status == ComputerAuditStatus.Pending ||
            ca.Status == ComputerAuditStatus.Running);

        if (candidateComputerIds is { Count: > 0 })
        {
            busyQuery = busyQuery.Where(ca => candidateComputerIds.Contains(ca.ComputerId));
        }

        return busyQuery
            .Select(ca => ca.ComputerId)
            .Distinct();
    }

    /// <summary>
    /// Splits selected active computers into eligible targets and those skipped because an audit is already in progress.
    /// </summary>
    public static (List<Computer> Eligible, List<Computer> SkippedInProgress) PartitionSelectedComputers(
        IReadOnlyList<Computer> selectedComputers,
        IReadOnlySet<int> busyComputerIds)
    {
        ArgumentNullException.ThrowIfNull(selectedComputers);
        ArgumentNullException.ThrowIfNull(busyComputerIds);

        var eligible = new List<Computer>(selectedComputers.Count);
        var skipped = new List<Computer>();

        foreach (var computer in selectedComputers)
        {
            if (busyComputerIds.Contains(computer.Id))
                skipped.Add(computer);
            else
                eligible.Add(computer);
        }

        return (eligible, skipped);
    }

    public static string FormatActivityLogAction(int runId, int computerCount) =>
        $"Started audit run #{runId} on {computerCount} computers";

    private async Task LoadPageDataAsync(CancellationToken ct)
    {
        Locations = await _db.Computers
            .AsNoTracking()
            .Where(c => c.IsActive && c.Location != "")
            .Select(c => c.Location)
            .Distinct()
            .OrderBy(l => l)
            .ToListAsync(ct);

        var query = _db.Computers
            .AsNoTracking()
            .Where(c => c.IsActive);

        if (!string.IsNullOrWhiteSpace(Location))
        {
            var trimmedLoc = Location.Trim();
            query = query.Where(c => c.Location == trimmedLoc);
        }

        Computers = await query
            .OrderBy(c => c.Name)
            .ToListAsync(ct);

        var visibleIds = Computers.Select(c => c.Id).ToList();
        if (visibleIds.Count > 0)
        {
            var busyList = await GetBusyComputerIdsQuery(_db.ComputerAudits.AsNoTracking(), visibleIds)
                .ToListAsync(ct);
            BusyComputerIds = busyList.ToHashSet();
        }
        else
        {
            BusyComputerIds = new HashSet<int>();
        }

        var settings = await _db.AppSettings
            .AsNoTracking()
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);

        ScoreGoodMin = ParseSettingInt(settings, AppSettingKeys.ScoreGoodMin, 90);
        ScoreFairMin = ParseSettingInt(settings, AppSettingKeys.ScoreFairMin, 70);
        ScorePoorMin = ParseSettingInt(settings, AppSettingKeys.ScorePoorMin, 50);
    }

    private static int ParseSettingInt(IReadOnlyDictionary<string, string> settings, string key, int fallback) =>
        settings.TryGetValue(key, out var raw) &&
        int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : fallback;
}

