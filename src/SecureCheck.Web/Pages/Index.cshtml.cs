using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages;

/// <summary>
/// Main security posture dashboard accessible to all authenticated roles (Administrator, Auditor, Viewer).
/// </summary>
public class IndexModel : PageModel
{
    private static readonly JsonSerializerOptions ChartJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;

    public IndexModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService)
    {
        _db = db;
        _authorizationService = authorizationService;
    }

    public bool CanAudit { get; private set; }
    public DashboardSummary Summary { get; private set; } = new();
    public IReadOnlyList<Alert> RecentAlerts { get; private set; } = Array.Empty<Alert>();
    public string RiskChartJson { get; private set; } = "{}";
    public string CategoryChartJson { get; private set; } = "{}";

    public async Task OnGetAsync()
    {
        var ct = HttpContext.RequestAborted;

        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;
        var thresholds = await ScoreThresholds.LoadAsync(_db, ct);

        var activeComputers = await _db.Computers
            .AsNoTracking()
            .Where(c => c.IsActive)
            .OrderBy(c => c.Name)
            .ToListAsync(ct);

        var inactiveCount = await _db.Computers
            .AsNoTracking()
            .CountAsync(c => !c.IsActive, ct);

        var openAlertCount = await _db.Alerts
            .AsNoTracking()
            .CountAsync(a => !a.IsAcknowledged, ct);

        RecentAlerts = await _db.Alerts
            .AsNoTracking()
            .Include(a => a.Computer)
            .Where(a => !a.IsAcknowledged)
            .OrderByDescending(a => a.CreatedAt)
            .ThenByDescending(a => a.Id)
            .Take(5)
            .ToListAsync(ct);

        var activeIds = activeComputers.Select(c => c.Id).ToList();
        var latestCompletedList = new List<ComputerAudit>();
        var latestAttemptList = new List<ComputerAudit>();

        if (activeIds.Count > 0)
        {
            // Project lightweight audit headers (deliberately excluding RawJson nvarchar(max)).
            var auditHeaders = await _db.ComputerAudits
                .AsNoTracking()
                .Where(ca => activeIds.Contains(ca.ComputerId))
                .Select(ca => new ComputerAudit
                {
                    Id = ca.Id,
                    AuditRunId = ca.AuditRunId,
                    ComputerId = ca.ComputerId,
                    Status = ca.Status,
                    StartedAt = ca.StartedAt,
                    FinishedAt = ca.FinishedAt,
                    Score = ca.Score,
                    OverallRisk = ca.OverallRisk,
                    PassedCount = ca.PassedCount,
                    FailedCount = ca.FailedCount,
                    ErrorCount = ca.ErrorCount
                })
                .ToListAsync(ct);

            latestCompletedList = auditHeaders
                .Where(ca => ca.Status == ComputerAuditStatus.Completed)
                .GroupBy(ca => ca.ComputerId)
                .Select(g => g
                    .OrderByDescending(ca => ca.FinishedAt ?? ca.StartedAt ?? DateTime.MinValue)
                    .ThenByDescending(ca => ca.Id)
                    .First())
                .ToList();

            latestAttemptList = auditHeaders
                .GroupBy(ca => ca.ComputerId)
                .Select(g => g
                    .OrderByDescending(ca => ca.FinishedAt ?? ca.StartedAt ?? DateTime.MinValue)
                    .ThenByDescending(ca => ca.Id)
                    .First())
                .ToList();

            if (latestCompletedList.Count > 0)
            {
                var latestCompletedIds = latestCompletedList.Select(ca => ca.Id).ToList();
                var failedChecks = await _db.CheckResults
                    .AsNoTracking()
                    .Where(cr => latestCompletedIds.Contains(cr.ComputerAuditId) && cr.Status == CheckStatus.Fail)
                    .Select(cr => new CheckResult
                    {
                        Id = cr.Id,
                        ComputerAuditId = cr.ComputerAuditId,
                        Category = cr.Category,
                        Status = cr.Status
                    })
                    .ToListAsync(ct);

                var failedByAuditId = failedChecks
                    .GroupBy(cr => cr.ComputerAuditId)
                    .ToDictionary(g => g.Key, g => g.ToList());

                foreach (var ca in latestCompletedList)
                {
                    if (failedByAuditId.TryGetValue(ca.Id, out var fails))
                    {
                        ca.CheckResults = fails;
                    }
                }
            }
        }

        Summary = AuditAnalyticsService.BuildDashboardSummary(
            activeComputers,
            latestCompletedList,
            latestAttemptList,
            inactiveCount,
            openAlertCount,
            thresholds);

        RiskChartJson = JsonSerializer.Serialize(new
        {
            labels = Summary.RiskLabels,
            counts = Summary.RiskCounts,
            colors = Summary.RiskColors
        }, ChartJsonOptions);

        CategoryChartJson = JsonSerializer.Serialize(new
        {
            labels = Summary.CategoryLabels,
            counts = Summary.CategoryFailedCounts
        }, ChartJsonOptions);
    }
}
