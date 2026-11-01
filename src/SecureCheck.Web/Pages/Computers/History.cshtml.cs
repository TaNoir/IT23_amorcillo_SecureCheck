using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Computers;

/// <summary>
/// Security score history line chart and past audit table for a single computer (/Computers/History/{id:int}).
/// Accessible to all authenticated roles via FallbackPolicy.
/// </summary>
public class HistoryModel : PageModel
{
    private static readonly JsonSerializerOptions ChartJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;

    public HistoryModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService)
    {
        _db = db;
        _authorizationService = authorizationService;
    }

    public bool CanAudit { get; private set; }
    public bool CanManage { get; private set; }
    public Computer Computer { get; private set; } = null!;
    public ExecutionMode ExecutionMode { get; private set; }
    public IReadOnlyList<ComputerHistoryRow> Audits { get; private set; } = Array.Empty<ComputerHistoryRow>();
    public bool HasChartPoints { get; private set; }
    public string HistoryChartJson { get; private set; } = "{}";

    public async Task<IActionResult> OnGetAsync(int id)
    {
        var ct = HttpContext.RequestAborted;

        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;
        CanManage = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Manage)).Succeeded;

        var computer = await _db.Computers
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == id, ct);

        if (computer is null)
            return NotFound();

        Computer = computer;
        ExecutionMode = PowerShellRunner.DetermineMode(computer.HostName);

        var thresholds = await ScoreThresholds.LoadAsync(_db, ct);

        // Project audit rows without loading RawJson nvarchar(max).
        var rawAudits = await _db.ComputerAudits
            .AsNoTracking()
            .Where(ca => ca.ComputerId == id)
            .Select(ca => new
            {
                ca.Id,
                ca.AuditRunId,
                RunCreatedAt = ca.AuditRun.CreatedAt,
                StartedByName = ca.AuditRun.StartedByName,
                ca.Status,
                ca.StartedAt,
                ca.FinishedAt,
                ca.Score,
                ca.OverallRisk,
                ca.PassedCount,
                ca.FailedCount,
                ca.ErrorCount,
                ca.ErrorMessage,
                ca.OsCaption
            })
            .ToListAsync(ct);

        Audits = rawAudits
            .OrderByDescending(a => a.FinishedAt ?? a.StartedAt ?? a.RunCreatedAt)
            .ThenByDescending(a => a.Id)
            .Select(a =>
            {
                var (scoreLabel, scoreBadge, scoreText) = thresholds.Describe(a.Score);
                var (riskLabel, riskBadge) = AuditAnalyticsService.DescribeComputerAuditRisk(a.Status, a.OverallRisk, a.Score);
                var timestamp = a.FinishedAt ?? a.StartedAt ?? a.RunCreatedAt;

                return new ComputerHistoryRow
                {
                    ComputerAuditId = a.Id,
                    AuditRunId = a.AuditRunId,
                    StartedByName = a.StartedByName,
                    TimestampUtc = timestamp,
                    Status = a.Status,
                    IsInProgress = a.Status is ComputerAuditStatus.Pending or ComputerAuditStatus.Running,
                    Score = a.Score,
                    ScoreLabel = scoreLabel,
                    ScoreBadgeClass = scoreBadge,
                    ScoreTextClass = scoreText,
                    OverallRiskDisplay = riskLabel,
                    OverallRiskBadgeClass = riskBadge,
                    PassedCount = a.PassedCount,
                    FailedCount = a.FailedCount,
                    ErrorCount = a.ErrorCount,
                    ErrorMessage = a.ErrorMessage,
                    OsCaption = a.OsCaption
                };
            })
            .ToList();

        var scoredChronological = Audits
            .Where(a => a.Status == ComputerAuditStatus.Completed && a.Score.HasValue)
            .OrderBy(a => a.TimestampUtc)
            .ThenBy(a => a.ComputerAuditId)
            .ToList();

        HasChartPoints = scoredChronological.Count > 0;
        if (HasChartPoints)
        {
            HistoryChartJson = JsonSerializer.Serialize(new
            {
                labels = scoredChronological
                    .Select(a => AuditAnalyticsService.FormatLocalDateTime(a.TimestampUtc, "yyyy-MM-dd HH:mm"))
                    .ToList(),
                scores = scoredChronological
                    .Select(a => a.Score!.Value)
                    .ToList(),
                pointColors = scoredChronological
                    .Select(a => thresholds.GetBrandHex(a.Score))
                    .ToList()
            }, ChartJsonOptions);
        }

        return Page();
    }

    public sealed class ComputerHistoryRow
    {
        public int ComputerAuditId { get; init; }
        public int AuditRunId { get; init; }
        public string StartedByName { get; init; } = string.Empty;
        public DateTime TimestampUtc { get; init; }
        public ComputerAuditStatus Status { get; init; }
        public bool IsInProgress { get; init; }
        public int? Score { get; init; }
        public string ScoreLabel { get; init; } = string.Empty;
        public string ScoreBadgeClass { get; init; } = string.Empty;
        public string ScoreTextClass { get; init; } = string.Empty;
        public string OverallRiskDisplay { get; init; } = string.Empty;
        public string OverallRiskBadgeClass { get; init; } = string.Empty;
        public int PassedCount { get; init; }
        public int FailedCount { get; init; }
        public int ErrorCount { get; init; }
        public string? ErrorMessage { get; init; }
        public string? OsCaption { get; init; }
    }
}

