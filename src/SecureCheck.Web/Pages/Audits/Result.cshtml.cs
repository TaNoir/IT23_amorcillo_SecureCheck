using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Audits;

/// <summary>
/// Detailed single-computer audit result (/Audits/Result/{computerAuditId:int}):
/// score header, prioritized "How to fix" steps, comparison with previous completed audit,
/// category-grouped check results in PROJECT_BRIEF order, and Admin-only collapsible RawJson.
/// </summary>
public class ResultModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;

    public ResultModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService)
    {
        _db = db;
        _authorizationService = authorizationService;
    }

    public bool CanAudit { get; private set; }
    public bool CanManage { get; private set; }

    public ComputerAudit Audit { get; private set; } = null!;
    public ExecutionMode ExecutionMode { get; private set; }
    public DateTime DisplayTimestampUtc { get; private set; }
    public string ScoreLabel { get; private set; } = "Not Evaluated";
    public string ScoreBadgeClass { get; private set; } = "status-error";
    public string ScoreTextClass { get; private set; } = "text-sc-gray";
    public string OverallRiskDisplay { get; private set; } = "—";
    public string OverallRiskBadgeClass { get; private set; } = string.Empty;

    public IReadOnlyList<CheckResult> FailedChecks { get; private set; } = Array.Empty<CheckResult>();
    public IReadOnlyList<CategoryResultGroup> CategoryGroups { get; private set; } = Array.Empty<CategoryResultGroup>();
    public AuditComparisonResult? Comparison { get; private set; }

    /// <summary>
    /// Populated ONLY when the current user satisfies ManagePolicy (Administrator).
    /// </summary>
    public string? PrettyRawJson { get; private set; }

    public async Task<IActionResult> OnGetAsync(int computerAuditId)
    {
        var ct = HttpContext.RequestAborted;

        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;
        CanManage = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Manage)).Succeeded;

        // Project ComputerAudit without RawJson first so non-administrators never load raw JSON into memory.
        var audit = await _db.ComputerAudits
            .AsNoTracking()
            .Include(ca => ca.Computer)
            .Include(ca => ca.AuditRun)
            .Include(ca => ca.CheckResults)
            .Where(ca => ca.Id == computerAuditId)
            .Select(ca => new ComputerAudit
            {
                Id = ca.Id,
                AuditRunId = ca.AuditRunId,
                AuditRun = ca.AuditRun,
                ComputerId = ca.ComputerId,
                Computer = ca.Computer,
                Status = ca.Status,
                StartedAt = ca.StartedAt,
                FinishedAt = ca.FinishedAt,
                Score = ca.Score,
                OverallRisk = ca.OverallRisk,
                PassedCount = ca.PassedCount,
                FailedCount = ca.FailedCount,
                ErrorCount = ca.ErrorCount,
                ErrorMessage = ca.ErrorMessage,
                OsCaption = ca.OsCaption,
                OsVersion = ca.OsVersion,
                PsVersion = ca.PsVersion,
                RawJson = CanManage ? ca.RawJson : null,
                CheckResults = ca.CheckResults
            })
            .FirstOrDefaultAsync(ct);

        if (audit is null)
            return NotFound();

        var thresholds = await ScoreThresholds.LoadAsync(_db, ct);
        var sortOrders = await _db.CheckDefinitions
            .AsNoTracking()
            .ToDictionaryAsync(cd => cd.Id, cd => cd.SortOrder, ct);

        PopulateViewModel(audit, thresholds, sortOrders, CanManage);

        if (audit.Status == ComputerAuditStatus.Completed)
        {
            var previousAudit = await AuditAnalyticsService
                .BuildPreviousCompletedAuditQuery(_db.ComputerAudits.AsNoTracking(), audit)
                .Select(ca => new ComputerAudit
                {
                    Id = ca.Id,
                    ComputerId = ca.ComputerId,
                    Status = ca.Status,
                    StartedAt = ca.StartedAt,
                    FinishedAt = ca.FinishedAt,
                    Score = ca.Score,
                    OverallRisk = ca.OverallRisk,
                    CheckResults = ca.CheckResults
                })
                .FirstOrDefaultAsync(ct);

            if (previousAudit is not null)
            {
                Comparison = AuditAnalyticsService.CompareAudits(audit, previousAudit);
            }
        }

        return Page();
    }

    internal void PopulateViewModel(
        ComputerAudit audit,
        ScoreThresholds thresholds,
        IReadOnlyDictionary<int, int>? sortOrders,
        bool canManage)
    {
        Audit = audit;
        CanManage = canManage;
        ExecutionMode = PowerShellRunner.DetermineMode(audit.Computer?.HostName);
        DisplayTimestampUtc = audit.FinishedAt ?? audit.StartedAt ?? audit.AuditRun?.CreatedAt ?? DateTime.UtcNow;

        (ScoreLabel, ScoreBadgeClass, ScoreTextClass) = thresholds.Describe(audit.Score);
        (OverallRiskDisplay, OverallRiskBadgeClass) =
            AuditAnalyticsService.DescribeComputerAuditRisk(audit.Status, audit.OverallRisk, audit.Score);

        FailedChecks = AuditAnalyticsService.OrderFailedChecksWorstFirst(audit.CheckResults, sortOrders);
        CategoryGroups = AuditAnalyticsService.GroupResultsByCategory(audit.CheckResults, sortOrders);

        PrettyRawJson = canManage && !string.IsNullOrWhiteSpace(audit.RawJson)
            ? AuditAnalyticsService.FormatJsonPretty(audit.RawJson)
            : null;
    }

    public static string GetCheckStatusIcon(CheckStatus status) => status switch
    {
        CheckStatus.Pass => "bi-check-circle-fill text-sc-green",
        CheckStatus.Fail => "bi-x-circle-fill text-sc-red",
        CheckStatus.Error => "bi-exclamation-triangle-fill text-sc-gray",
        CheckStatus.Skipped => "bi-dash-circle text-sc-gray",
        _ => "bi-question-circle text-sc-gray"
    };
}

