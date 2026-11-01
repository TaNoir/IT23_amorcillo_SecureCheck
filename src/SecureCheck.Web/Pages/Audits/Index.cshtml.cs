using System.Globalization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Audits;

/// <summary>
/// Paged audit run history (20 runs per page) with local date-range filtering.
/// Accessible to all authenticated roles via FallbackPolicy.
/// </summary>
public class IndexModel : PageModel
{
    public const int PageSize = 20;

    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;

    public IndexModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService)
    {
        _db = db;
        _authorizationService = authorizationService;
    }

    [BindProperty(SupportsGet = true)]
    public DateOnly? From { get; set; }

    [BindProperty(SupportsGet = true)]
    public DateOnly? To { get; set; }

    [BindProperty(SupportsGet = true)]
    public int PageNumber { get; set; } = 1;

    public bool CanAudit { get; private set; }
    public int TotalCount { get; private set; }
    public int TotalPages { get; private set; } = 1;
    public IReadOnlyList<AuditRunRow> Runs { get; private set; } = Array.Empty<AuditRunRow>();

    public string? FromInputValue => From?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    public string? ToInputValue => To?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    public async Task OnGetAsync()
    {
        var ct = HttpContext.RequestAborted;

        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;
        var thresholds = await ScoreThresholds.LoadAsync(_db, ct);

        var (startUtc, endUtcExclusive, normFrom, normTo) = AuditAnalyticsService.ResolveDateRangeUtc(From, To);
        From = normFrom;
        To = normTo;

        var query = ApplyDateFilter(_db.AuditRuns.AsNoTracking(), startUtc, endUtcExclusive);

        TotalCount = await query.CountAsync(ct);
        TotalPages = CalculateTotalPages(TotalCount, PageSize);
        PageNumber = Math.Clamp(PageNumber, 1, TotalPages);

        var pageRuns = await query
            .OrderByDescending(r => r.CreatedAt)
            .ThenByDescending(r => r.Id)
            .Skip((PageNumber - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync(ct);

        if (pageRuns.Count == 0)
        {
            Runs = Array.Empty<AuditRunRow>();
            return;
        }

        var runIds = pageRuns.Select(r => r.Id).ToList();
        var scoreRows = await _db.ComputerAudits
            .AsNoTracking()
            .Where(ca => runIds.Contains(ca.AuditRunId))
            .Select(ca => new { ca.AuditRunId, ca.Score })
            .ToListAsync(ct);

        var scoresByRunId = scoreRows
            .GroupBy(x => x.AuditRunId)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Score).ToList());

        Runs = pageRuns.Select(run =>
        {
            scoresByRunId.TryGetValue(run.Id, out var runScores);
            var avgScore = runScores is not null ? AuditAnalyticsService.ComputeAverageScore(runScores) : null;
            var (scoreLabel, scoreBadge, scoreText) = thresholds.Describe(avgScore);
            var isInProgress = run.Status is AuditRunStatus.Queued or AuditRunStatus.Running;

            return new AuditRunRow
            {
                Id = run.Id,
                CreatedAtUtc = run.CreatedAt,
                StartedAtUtc = run.StartedAt,
                FinishedAtUtc = run.FinishedAt,
                StartedByName = run.StartedByName,
                Status = run.Status,
                TotalComputers = run.TotalComputers,
                CompletedComputers = run.TotalComputers > 0
                    ? Math.Clamp(run.CompletedComputers, 0, run.TotalComputers)
                    : 0,
                IsInProgress = isInProgress,
                AverageScore = avgScore,
                AverageScoreLabel = scoreLabel,
                AverageScoreBadgeClass = scoreBadge,
                AverageScoreTextClass = scoreText
            };
        }).ToList();
    }

    public static IQueryable<AuditRun> ApplyDateFilter(
        IQueryable<AuditRun> query,
        DateTime? startUtcInclusive,
        DateTime? endUtcExclusive)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (startUtcInclusive.HasValue)
        {
            query = query.Where(r => r.CreatedAt >= startUtcInclusive.Value);
        }

        if (endUtcExclusive.HasValue)
        {
            query = query.Where(r => r.CreatedAt < endUtcExclusive.Value);
        }

        return query;
    }

    public static int CalculateTotalPages(int totalItems, int pageSize = PageSize)
    {
        if (pageSize <= 0 || totalItems <= 0)
            return 1;

        return (int)Math.Ceiling((double)totalItems / pageSize);
    }

    public sealed class AuditRunRow
    {
        public int Id { get; init; }
        public DateTime CreatedAtUtc { get; init; }
        public DateTime? StartedAtUtc { get; init; }
        public DateTime? FinishedAtUtc { get; init; }
        public string StartedByName { get; init; } = string.Empty;
        public AuditRunStatus Status { get; init; }
        public int TotalComputers { get; init; }
        public int CompletedComputers { get; init; }
        public bool IsInProgress { get; init; }
        public int? AverageScore { get; init; }
        public string AverageScoreLabel { get; init; } = string.Empty;
        public string AverageScoreBadgeClass { get; init; } = string.Empty;
        public string AverageScoreTextClass { get; init; } = string.Empty;
    }
}

