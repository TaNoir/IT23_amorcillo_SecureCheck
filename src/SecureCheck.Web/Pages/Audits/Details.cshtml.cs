using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Audits;

/// <summary>
/// Per-computer summary view for a batch AuditRun (/Audits/Details/{runId:int}).
/// Matches the "View Results" link from /Audits/Progress/{runId:int}.
/// </summary>
public class DetailsModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;

    public DetailsModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService)
    {
        _db = db;
        _authorizationService = authorizationService;
    }

    public bool CanAudit { get; private set; }
    public AuditRun Run { get; private set; } = null!;
    public bool IsInProgress { get; private set; }
    public int? AverageScore { get; private set; }
    public string AverageScoreLabel { get; private set; } = "Not Evaluated";
    public string AverageScoreBadgeClass { get; private set; } = "status-error";
    public string AverageScoreTextClass { get; private set; } = "text-sc-gray";
    public int HighOrCriticalCount { get; private set; }
    public IReadOnlyList<RunComputerRow> Computers { get; private set; } = Array.Empty<RunComputerRow>();

    public async Task<IActionResult> OnGetAsync(int runId)
    {
        var ct = HttpContext.RequestAborted;

        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;

        var run = await _db.AuditRuns
            .AsNoTracking()
            .FirstOrDefaultAsync(r => r.Id == runId, ct);

        if (run is null)
            return NotFound();

        var thresholds = await ScoreThresholds.LoadAsync(_db, ct);

        // Project ComputerAudit summary rows without loading RawJson nvarchar(max).
        var auditRows = await _db.ComputerAudits
            .AsNoTracking()
            .Where(ca => ca.AuditRunId == runId)
            .Select(ca => new
            {
                ca.Id,
                ca.ComputerId,
                ComputerName = ca.Computer.Name,
                HostName = ca.Computer.HostName,
                Location = ca.Computer.Location,
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

        Run = run;
        IsInProgress = run.Status is AuditRunStatus.Queued or AuditRunStatus.Running;

        AverageScore = AuditAnalyticsService.ComputeAverageScore(auditRows.Select(r => r.Score));
        (AverageScoreLabel, AverageScoreBadgeClass, AverageScoreTextClass) = thresholds.Describe(AverageScore);

        HighOrCriticalCount = auditRows.Count(r =>
            r.Status == ComputerAuditStatus.Completed &&
            r.OverallRisk is RiskLevel.High or RiskLevel.Critical);

        Computers = auditRows
            .OrderByDescending(r => AuditAnalyticsService.GetAttentionRiskRank(
                r.Status == ComputerAuditStatus.Completed,
                r.OverallRisk,
                r.Score))
            .ThenBy(r => r.Score ?? int.MinValue)
            .ThenBy(r => r.ComputerName, StringComparer.OrdinalIgnoreCase)
            .Select(r =>
            {
                var mode = PowerShellRunner.DetermineMode(r.HostName);
                var (scoreLabel, scoreBadge, scoreText) = thresholds.Describe(r.Score);
                var (riskLabel, riskBadge) = AuditAnalyticsService.DescribeComputerAuditRisk(r.Status, r.OverallRisk, r.Score);

                return new RunComputerRow
                {
                    ComputerAuditId = r.Id,
                    ComputerId = r.ComputerId,
                    ComputerName = r.ComputerName,
                    HostName = r.HostName,
                    Location = r.Location,
                    ExecutionMode = mode,
                    Status = r.Status,
                    FinishedAtUtc = r.FinishedAt ?? r.StartedAt,
                    Score = r.Score,
                    ScoreLabel = scoreLabel,
                    ScoreBadgeClass = scoreBadge,
                    ScoreTextClass = scoreText,
                    OverallRiskDisplay = riskLabel,
                    OverallRiskBadgeClass = riskBadge,
                    PassedCount = r.PassedCount,
                    FailedCount = r.FailedCount,
                    ErrorCount = r.ErrorCount,
                    ErrorMessage = r.ErrorMessage,
                    OsCaption = r.OsCaption
                };
            })
            .ToList();

        return Page();
    }

    public sealed class RunComputerRow
    {
        public int ComputerAuditId { get; init; }
        public int ComputerId { get; init; }
        public string ComputerName { get; init; } = string.Empty;
        public string HostName { get; init; } = string.Empty;
        public string Location { get; init; } = string.Empty;
        public ExecutionMode ExecutionMode { get; init; }
        public ComputerAuditStatus Status { get; init; }
        public DateTime? FinishedAtUtc { get; init; }
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

