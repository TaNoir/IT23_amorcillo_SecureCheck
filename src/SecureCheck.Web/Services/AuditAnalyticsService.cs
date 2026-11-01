using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>
/// Score threshold configuration loaded from AppSettings (defaults: Good ≥ 90, Fair ≥ 70, Poor ≥ 50).
/// </summary>
public readonly record struct ScoreThresholds(int GoodMin, int FairMin, int PoorMin)
{
    public static ScoreThresholds Default => new(90, 70, 50);

    public static ScoreThresholds FromDictionary(IReadOnlyDictionary<string, string>? settings)
    {
        if (settings is null)
            return Default;

        var good = ParseInt(settings, AppSettingKeys.ScoreGoodMin, 90);
        var fair = ParseInt(settings, AppSettingKeys.ScoreFairMin, 70);
        var poor = ParseInt(settings, AppSettingKeys.ScorePoorMin, 50);
        return new ScoreThresholds(good, fair, poor);
    }

    public static async Task<ScoreThresholds> LoadAsync(ApplicationDbContext db, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);

        var settings = await db.AppSettings
            .AsNoTracking()
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);

        return FromDictionary(settings);
    }

    public (string Label, string BadgeClass, string TextClass) Describe(int? score) =>
        AuditEvaluator.DescribeScore(score, GoodMin, FairMin, PoorMin);

    public string GetBrandHex(int? score)
    {
        if (!score.HasValue)
            return "#8A94A6";
        if (score.Value >= GoodMin)
            return "#168653";
        if (score.Value >= FairMin)
            return "#E5B72E";
        if (score.Value >= PoorMin)
            return "#EC8A3C";
        return "#F45D5B";
    }

    private static int ParseInt(IReadOnlyDictionary<string, string> settings, string key, int fallback) =>
        settings.TryGetValue(key, out var raw) &&
        int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : fallback;
}

/// <summary>
/// Grouped CheckResult rows for a single CheckCategory in PROJECT_BRIEF order.
/// </summary>
public sealed class CategoryResultGroup
{
    public CheckCategory Category { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string IconClass { get; init; } = "bi-shield-check";
    public IReadOnlyList<CheckResult> Results { get; init; } = Array.Empty<CheckResult>();
    public int PassedCount { get; init; }
    public int FailedCount { get; init; }
    public int ErrorCount { get; init; }
    public int SkippedCount { get; init; }
}

/// <summary>
/// Outcome of comparing a completed ComputerAudit against the previous completed ComputerAudit for the same computer.
/// </summary>
public sealed class AuditComparisonResult
{
    public int PreviousComputerAuditId { get; init; }
    public DateTime? PreviousFinishedAtUtc { get; init; }
    public int? PreviousScore { get; init; }
    public int? CurrentScore { get; init; }
    public int? ScoreDelta { get; init; }
    public string ScoreDeltaDisplay { get; init; } = "N/A";
    public string ScoreDeltaBadgeClass { get; init; } = "status-error";
    public string ScoreDeltaTextClass { get; init; } = "text-sc-gray";
    public IReadOnlyList<CheckResult> NewlyFailing { get; init; } = Array.Empty<CheckResult>();
    public IReadOnlyList<CheckResult> FixedSinceLastAudit { get; init; } = Array.Empty<CheckResult>();
    public IReadOnlyList<CheckResult> StillFailing { get; init; } = Array.Empty<CheckResult>();
}

/// <summary>
/// Single row in the Dashboard "Computers needing attention" table.
/// </summary>
public sealed class ComputerAttentionRow
{
    public int ComputerId { get; init; }
    public string ComputerName { get; init; } = string.Empty;
    public string HostName { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public int? LatestResultAuditId { get; init; }
    public DateTime? LastAuditedAtUtc { get; init; }
    public int? Score { get; init; }
    public string ScoreLabel { get; init; } = "Not Evaluated";
    public string ScoreBadgeClass { get; init; } = "status-error";
    public string ScoreTextClass { get; init; } = "text-sc-gray";
    public RiskLevel? OverallRisk { get; init; }
    public string OverallRiskDisplay { get; init; } = "Not audited";
    public string OverallRiskBadgeClass { get; init; } = "status-error";
    public int FailedCount { get; init; }
    public int PassedCount { get; init; }
    public int ErrorCount { get; init; }
    public bool HasCompletedAudit { get; init; }
    public string? LatestAttemptNote { get; init; }
    public int RiskSortRank { get; init; }
}

/// <summary>
/// Aggregated KPI, chart, and table data for the SecureCheck Dashboard (/Index).
/// </summary>
public sealed class DashboardSummary
{
    public int TotalComputers { get; init; }
    public int InactiveComputers { get; init; }
    public int? AverageScore { get; init; }
    public string AverageScoreLabel { get; init; } = "Not Evaluated";
    public string AverageScoreBadgeClass { get; init; } = "status-error";
    public string AverageScoreTextClass { get; init; } = "text-sc-gray";
    public int HighOrCriticalComputers { get; init; }
    public int OpenAlerts { get; init; }
    public DateTime? LastAuditAtUtc { get; init; }
    public IReadOnlyList<string> RiskLabels { get; init; } = Array.Empty<string>();
    public IReadOnlyList<int> RiskCounts { get; init; } = Array.Empty<int>();
    public IReadOnlyList<string> RiskColors { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> CategoryLabels { get; init; } = Array.Empty<string>();
    public IReadOnlyList<int> CategoryFailedCounts { get; init; } = Array.Empty<int>();
    public IReadOnlyList<ComputerAttentionRow> AttentionComputers { get; init; } = Array.Empty<ComputerAttentionRow>();
}

/// <summary>
/// Pure, stateless domain calculations for Phase 7 Dashboard, Audit History, Run Details,
/// Computer Result comparison/grouping, and Computer History.
/// </summary>
public static class AuditAnalyticsService
{
    private static readonly JsonSerializerOptions PrettyJsonOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Canonical category order defined in PROJECT_BRIEF:
    /// Firewall, Updates, Antivirus, Accounts, Services &amp; Features.
    /// </summary>
    public static readonly IReadOnlyList<CheckCategory> BriefCategoryOrder = new[]
    {
        CheckCategory.Firewall,
        CheckCategory.Updates,
        CheckCategory.Antivirus,
        CheckCategory.Accounts,
        CheckCategory.ServicesAndFeatures
    };

    /// <summary>
    /// Brand colors for the 6 dashboard doughnut risk buckets:
    /// Secure (#168653), Low (#168653), Medium (#E5B72E), High (#EC8A3C), Critical (#F45D5B), Not audited (#8A94A6).
    /// </summary>
    public static readonly IReadOnlyList<string> DoughnutRiskLabels = new[]
    {
        "Secure",
        "Low",
        "Medium",
        "High",
        "Critical",
        "Not audited"
    };

    public static readonly IReadOnlyList<string> DoughnutRiskColors = new[]
    {
        "#168653",
        "#168653",
        "#E5B72E",
        "#EC8A3C",
        "#F45D5B",
        "#8A94A6"
    };

    public static int GetCategoryOrder(CheckCategory category) => category switch
    {
        CheckCategory.Firewall => 0,
        CheckCategory.Updates => 1,
        CheckCategory.Antivirus => 2,
        CheckCategory.Accounts => 3,
        CheckCategory.ServicesAndFeatures => 4,
        _ => 99
    };

    public static string GetCategoryIcon(CheckCategory category) => category switch
    {
        CheckCategory.Firewall => "bi-bricks",
        CheckCategory.Updates => "bi-arrow-repeat",
        CheckCategory.Antivirus => "bi-shield-shaded",
        CheckCategory.Accounts => "bi-person-badge",
        CheckCategory.ServicesAndFeatures => "bi-hdd-rack",
        _ => "bi-shield-check"
    };

    public static (string Label, string BadgeClass) DescribeCompletedRisk(RiskLevel? overallRisk, int? score)
    {
        if (overallRisk.HasValue)
            return (overallRisk.Value.ToString(), overallRisk.Value.ToBadgeClass());

        if (score.HasValue)
            return ("Secure", "risk-low");

        return ("Not Evaluated", "status-error");
    }

    public static (string Label, string BadgeClass) DescribeComputerAuditRisk(
        ComputerAuditStatus status,
        RiskLevel? overallRisk,
        int? score)
    {
        if (status != ComputerAuditStatus.Completed)
            return ("—", string.Empty);

        return DescribeCompletedRisk(overallRisk, score);
    }

    /// <summary>
    /// Groups CheckResult rows into Bootstrap card sections strictly in PROJECT_BRIEF category order.
    /// </summary>
    public static List<CategoryResultGroup> GroupResultsByCategory(
        IEnumerable<CheckResult> results,
        IReadOnlyDictionary<int, int>? sortOrderByDefinitionId = null)
    {
        ArgumentNullException.ThrowIfNull(results);

        var materialized = results.Where(r => r is not null).ToList();

        return materialized
            .GroupBy(r => r.Category)
            .OrderBy(g => GetCategoryOrder(g.Key))
            .Select(g =>
            {
                var orderedRows = g
                    .OrderBy(r => ResolveSortOrder(r, sortOrderByDefinitionId))
                    .ThenBy(r => r.Code, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                return new CategoryResultGroup
                {
                    Category = g.Key,
                    DisplayName = g.Key.ToDisplayName(),
                    IconClass = GetCategoryIcon(g.Key),
                    Results = orderedRows,
                    PassedCount = orderedRows.Count(r => r.Status == CheckStatus.Pass),
                    FailedCount = orderedRows.Count(r => r.Status == CheckStatus.Fail),
                    ErrorCount = orderedRows.Count(r => r.Status == CheckStatus.Error),
                    SkippedCount = orderedRows.Count(r => r.Status == CheckStatus.Skipped)
                };
            })
            .ToList();
    }

    /// <summary>
    /// Filters Failed CheckResult rows and sorts them Critical -> High -> Medium -> Low,
    /// then by brief category order and check SortOrder/Code.
    /// </summary>
    public static List<CheckResult> OrderFailedChecksWorstFirst(
        IEnumerable<CheckResult> results,
        IReadOnlyDictionary<int, int>? sortOrderByDefinitionId = null)
    {
        ArgumentNullException.ThrowIfNull(results);

        return results
            .Where(r => r is not null && r.Status == CheckStatus.Fail)
            .OrderByDescending(r => r.RiskLevel)
            .ThenBy(r => GetCategoryOrder(r.Category))
            .ThenBy(r => ResolveSortOrder(r, sortOrderByDefinitionId))
            .ThenBy(r => r.Code, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Selects the most recent Completed ComputerAudit for the same computer that finished chronologically
    /// before <paramref name="current"/> (breaking identical-timestamp ties by Id &lt; current.Id).
    /// </summary>
    public static ComputerAudit? SelectPreviousCompletedAudit(
        ComputerAudit current,
        IEnumerable<ComputerAudit> candidates)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(candidates);

        var currentTime = current.FinishedAt ?? current.StartedAt;

        return candidates
            .Where(ca =>
                ca is not null &&
                ca.ComputerId == current.ComputerId &&
                ca.Id != current.Id &&
                ca.Status == ComputerAuditStatus.Completed &&
                IsPriorAudit(ca, current.Id, currentTime))
            .OrderByDescending(ca => ca.FinishedAt ?? ca.StartedAt ?? DateTime.MinValue)
            .ThenByDescending(ca => ca.Id)
            .FirstOrDefault();
    }

    /// <summary>
    /// Builds an EF Core query that locates the most recent Completed ComputerAudit for the same computer
    /// occurring prior to <paramref name="current"/>.
    /// </summary>
    public static IQueryable<ComputerAudit> BuildPreviousCompletedAuditQuery(
        IQueryable<ComputerAudit> query,
        ComputerAudit current)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(current);

        var baseQuery = query.Where(ca =>
            ca.ComputerId == current.ComputerId &&
            ca.Id != current.Id &&
            ca.Status == ComputerAuditStatus.Completed);

        if (current.FinishedAt.HasValue)
        {
            var finishedAt = current.FinishedAt.Value;
            baseQuery = baseQuery.Where(ca =>
                (ca.FinishedAt.HasValue && ca.FinishedAt.Value < finishedAt) ||
                (ca.FinishedAt.HasValue && ca.FinishedAt.Value == finishedAt && ca.Id < current.Id) ||
                (!ca.FinishedAt.HasValue && ca.Id < current.Id));
        }
        else
        {
            baseQuery = baseQuery.Where(ca => ca.Id < current.Id);
        }

        return baseQuery
            .OrderByDescending(ca => ca.FinishedAt)
            .ThenByDescending(ca => ca.Id);
    }

    /// <summary>
    /// Compares <paramref name="current"/> against <paramref name="previous"/> by check Code:
    /// - Newly failing: current == Fail and previous != Fail (or missing in previous)
    /// - Fixed since last audit: current == Pass and previous == Fail
    /// - Still failing: current == Fail and previous == Fail
    /// Plus formatted score delta ("+18", "-10", "0", or "N/A").
    /// </summary>
    public static AuditComparisonResult CompareAudits(ComputerAudit current, ComputerAudit previous)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(previous);

        var prevByCode = new Dictionary<string, CheckResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var prev in previous.CheckResults)
        {
            if (prev is not null && !string.IsNullOrWhiteSpace(prev.Code))
            {
                prevByCode.TryAdd(prev.Code.Trim(), prev);
            }
        }

        var newlyFailing = new List<CheckResult>();
        var fixedChecks = new List<CheckResult>();
        var stillFailing = new List<CheckResult>();

        foreach (var curr in current.CheckResults)
        {
            if (curr is null || string.IsNullOrWhiteSpace(curr.Code))
                continue;

            var hasPrev = prevByCode.TryGetValue(curr.Code.Trim(), out var prev);

            if (curr.Status == CheckStatus.Fail)
            {
                if (hasPrev && prev!.Status == CheckStatus.Fail)
                {
                    stillFailing.Add(curr);
                }
                else
                {
                    newlyFailing.Add(curr);
                }
            }
            else if (curr.Status == CheckStatus.Pass && hasPrev && prev!.Status == CheckStatus.Fail)
            {
                fixedChecks.Add(curr);
            }
        }

        int? delta = current.Score.HasValue && previous.Score.HasValue
            ? current.Score.Value - previous.Score.Value
            : null;

        var (deltaDisplay, deltaBadge, deltaText) = DescribeScoreDelta(delta);

        return new AuditComparisonResult
        {
            PreviousComputerAuditId = previous.Id,
            PreviousFinishedAtUtc = previous.FinishedAt ?? previous.StartedAt,
            PreviousScore = previous.Score,
            CurrentScore = current.Score,
            ScoreDelta = delta,
            ScoreDeltaDisplay = deltaDisplay,
            ScoreDeltaBadgeClass = deltaBadge,
            ScoreDeltaTextClass = deltaText,
            NewlyFailing = SortComparisonItems(newlyFailing),
            FixedSinceLastAudit = SortComparisonItems(fixedChecks),
            StillFailing = SortComparisonItems(stillFailing)
        };
    }

    public static string FormatScoreDelta(int? delta) => DescribeScoreDelta(delta).Display;

    public static (string Display, string BadgeClass, string TextClass) DescribeScoreDelta(int? delta)
    {
        if (!delta.HasValue)
            return ("N/A", "status-error", "text-sc-gray");

        if (delta.Value > 0)
            return ($"+{delta.Value.ToString(CultureInfo.InvariantCulture)}", "risk-low", "text-sc-green");

        if (delta.Value < 0)
            return (delta.Value.ToString(CultureInfo.InvariantCulture), "risk-critical", "text-sc-red");

        return ("0", "status-error", "text-sc-gray");
    }

    /// <summary>
    /// Computes all Dashboard summary KPIs, 6-bucket risk doughnut counts, 5-category failed check counts
    /// across each active computer's latest completed audit, and sorted "Computers needing attention" rows.
    /// </summary>
    public static DashboardSummary BuildDashboardSummary(
        IReadOnlyList<Computer> activeComputers,
        IReadOnlyList<ComputerAudit> latestCompletedAudits,
        IReadOnlyList<ComputerAudit> latestAnyAudits,
        int inactiveComputerCount,
        int openAlertCount,
        ScoreThresholds thresholds)
    {
        ArgumentNullException.ThrowIfNull(activeComputers);
        ArgumentNullException.ThrowIfNull(latestCompletedAudits);
        ArgumentNullException.ThrowIfNull(latestAnyAudits);

        var completedByComputerId = latestCompletedAudits
            .Where(ca => ca.Status == ComputerAuditStatus.Completed)
            .GroupBy(ca => ca.ComputerId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(ca => ca.FinishedAt ?? ca.StartedAt ?? DateTime.MinValue)
                      .ThenByDescending(ca => ca.Id)
                      .First());

        var latestAttemptByComputerId = latestAnyAudits
            .GroupBy(ca => ca.ComputerId)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(ca => ca.FinishedAt ?? ca.StartedAt ?? DateTime.MinValue)
                      .ThenByDescending(ca => ca.Id)
                      .First());

        // Risk doughnut buckets: 0=Secure, 1=Low, 2=Medium, 3=High, 4=Critical, 5=Not audited
        var riskCounts = new int[6];
        var categoryFailures = BriefCategoryOrder.ToDictionary(cat => cat, _ => 0);

        var scores = new List<int>(activeComputers.Count);
        var highOrCriticalCount = 0;
        DateTime? lastAuditAtUtc = null;

        var attentionRows = new List<ComputerAttentionRow>(activeComputers.Count);

        foreach (var computer in activeComputers)
        {
            completedByComputerId.TryGetValue(computer.Id, out var latestCompleted);
            latestAttemptByComputerId.TryGetValue(computer.Id, out var latestAttempt);

            if (latestCompleted is not null)
            {
                var auditTimestamp = latestCompleted.FinishedAt ?? latestCompleted.StartedAt ?? computer.LastAuditedAt;
                if (auditTimestamp.HasValue && (!lastAuditAtUtc.HasValue || auditTimestamp.Value > lastAuditAtUtc.Value))
                {
                    lastAuditAtUtc = auditTimestamp.Value;
                }

                if (latestCompleted.Score.HasValue)
                {
                    scores.Add(latestCompleted.Score.Value);
                }

                if (latestCompleted.OverallRisk is RiskLevel.High or RiskLevel.Critical)
                {
                    highOrCriticalCount++;
                }

                // Count risk bucket
                if (latestCompleted.OverallRisk.HasValue)
                {
                    var bucketIndex = latestCompleted.OverallRisk.Value switch
                    {
                        RiskLevel.Low => 1,
                        RiskLevel.Medium => 2,
                        RiskLevel.High => 3,
                        RiskLevel.Critical => 4,
                        _ => 5
                    };
                    riskCounts[bucketIndex]++;
                }
                else if (latestCompleted.Score.HasValue)
                {
                    riskCounts[0]++; // Secure
                }
                else
                {
                    riskCounts[5]++; // Not Evaluated -> Not audited bucket
                }

                // Sum failed checks per category from this computer's latest completed audit
                foreach (var cr in latestCompleted.CheckResults)
                {
                    if (cr is not null && cr.Status == CheckStatus.Fail && categoryFailures.ContainsKey(cr.Category))
                    {
                        categoryFailures[cr.Category]++;
                    }
                }

                var (scoreLabel, scoreBadge, scoreText) = thresholds.Describe(latestCompleted.Score);
                var (riskLabel, riskBadge) = DescribeCompletedRisk(latestCompleted.OverallRisk, latestCompleted.Score);

                string? attemptNote = null;
                if (latestAttempt is not null &&
                    latestAttempt.Id != latestCompleted.Id &&
                    latestAttempt.Status is ComputerAuditStatus.Unreachable or ComputerAuditStatus.Failed)
                {
                    attemptNote = $"Latest attempt: {latestAttempt.Status.ToDisplayName()}";
                }

                attentionRows.Add(new ComputerAttentionRow
                {
                    ComputerId = computer.Id,
                    ComputerName = computer.Name,
                    HostName = computer.HostName,
                    Location = computer.Location,
                    LatestResultAuditId = latestCompleted.Id,
                    LastAuditedAtUtc = auditTimestamp,
                    Score = latestCompleted.Score,
                    ScoreLabel = scoreLabel,
                    ScoreBadgeClass = scoreBadge,
                    ScoreTextClass = scoreText,
                    OverallRisk = latestCompleted.OverallRisk,
                    OverallRiskDisplay = riskLabel,
                    OverallRiskBadgeClass = riskBadge,
                    FailedCount = latestCompleted.FailedCount,
                    PassedCount = latestCompleted.PassedCount,
                    ErrorCount = latestCompleted.ErrorCount,
                    HasCompletedAudit = true,
                    LatestAttemptNote = attemptNote,
                    RiskSortRank = GetAttentionRiskRank(hasCompletedAudit: true, latestCompleted.OverallRisk, latestCompleted.Score)
                });
            }
            else
            {
                riskCounts[5]++; // Not audited

                string? attemptNote = null;
                int? fallbackAuditId = null;
                if (latestAttempt is not null &&
                    latestAttempt.Status is ComputerAuditStatus.Unreachable or ComputerAuditStatus.Failed)
                {
                    attemptNote = $"Last attempt: {latestAttempt.Status.ToDisplayName()}";
                    fallbackAuditId = latestAttempt.Id;
                }

                attentionRows.Add(new ComputerAttentionRow
                {
                    ComputerId = computer.Id,
                    ComputerName = computer.Name,
                    HostName = computer.HostName,
                    Location = computer.Location,
                    LatestResultAuditId = fallbackAuditId,
                    LastAuditedAtUtc = null,
                    Score = null,
                    ScoreLabel = "Not audited",
                    ScoreBadgeClass = "status-error",
                    ScoreTextClass = "text-sc-gray",
                    OverallRisk = null,
                    OverallRiskDisplay = "Not audited",
                    OverallRiskBadgeClass = "status-error",
                    HasCompletedAudit = false,
                    LatestAttemptNote = attemptNote,
                    RiskSortRank = GetAttentionRiskRank(hasCompletedAudit: false, overallRisk: null, score: null)
                });
            }
        }

        int? averageScore = scores.Count > 0
            ? (int)Math.Round(scores.Average(), MidpointRounding.AwayFromZero)
            : null;

        var (avgLabel, avgBadge, avgText) = thresholds.Describe(averageScore);

        var sortedAttention = attentionRows
            .OrderByDescending(r => r.RiskSortRank)
            .ThenBy(r => r.Score ?? int.MinValue)
            .ThenBy(r => r.ComputerName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new DashboardSummary
        {
            TotalComputers = activeComputers.Count,
            InactiveComputers = Math.Max(0, inactiveComputerCount),
            AverageScore = averageScore,
            AverageScoreLabel = avgLabel,
            AverageScoreBadgeClass = avgBadge,
            AverageScoreTextClass = avgText,
            HighOrCriticalComputers = highOrCriticalCount,
            OpenAlerts = Math.Max(0, openAlertCount),
            LastAuditAtUtc = lastAuditAtUtc,
            RiskLabels = DoughnutRiskLabels,
            RiskCounts = riskCounts,
            RiskColors = DoughnutRiskColors,
            CategoryLabels = BriefCategoryOrder.Select(c => c.ToDisplayName()).ToList(),
            CategoryFailedCounts = BriefCategoryOrder.Select(c => categoryFailures[c]).ToList(),
            AttentionComputers = sortedAttention
        };
    }

    /// <summary>
    /// Attention table risk rank (higher = needs attention sooner):
    /// Critical (5) -> High (4) -> Medium (3) -> Low (2) -> Not audited / Not Evaluated (1) -> Secure (0).
    /// </summary>
    public static int GetAttentionRiskRank(bool hasCompletedAudit, RiskLevel? overallRisk, int? score)
    {
        if (!hasCompletedAudit)
            return 1;

        if (overallRisk.HasValue)
        {
            return overallRisk.Value switch
            {
                RiskLevel.Critical => 5,
                RiskLevel.High => 4,
                RiskLevel.Medium => 3,
                RiskLevel.Low => 2,
                _ => 1
            };
        }

        return score.HasValue ? 0 : 1;
    }

    /// <summary>
    /// Computes average score across scored ComputerAudit rows in an AuditRun (null if none have a score).
    /// </summary>
    public static int? ComputeAverageScore(IEnumerable<int?> scores)
    {
        ArgumentNullException.ThrowIfNull(scores);

        var sum = 0;
        var count = 0;
        foreach (var s in scores)
        {
            if (s.HasValue)
            {
                sum += s.Value;
                count++;
            }
        }

        return count > 0
            ? (int)Math.Round((double)sum / count, MidpointRounding.AwayFromZero)
            : null;
    }

    /// <summary>
    /// Converts optional local calendar DateOnly bounds into UTC [StartInclusive, EndExclusive) timestamps.
    /// Automatically swaps From and To if From &gt; To.
    /// </summary>
    public static (DateTime? StartUtcInclusive, DateTime? EndUtcExclusive, DateOnly? NormalizedFrom, DateOnly? NormalizedTo)
        ResolveDateRangeUtc(DateOnly? from, DateOnly? to, TimeZoneInfo? timeZone = null)
    {
        var tz = timeZone ?? TimeZoneInfo.Local;
        var normFrom = from;
        var normTo = to;

        if (normFrom.HasValue && normTo.HasValue && normFrom.Value > normTo.Value)
        {
            (normFrom, normTo) = (normTo, normFrom);
        }

        DateTime? startUtc = normFrom.HasValue
            ? ConvertLocalStartOfDayToUtc(normFrom.Value, tz)
            : null;

        DateTime? endUtcExclusive = normTo.HasValue
            ? ConvertLocalStartOfDayToUtc(normTo.Value.AddDays(1), tz)
            : null;

        return (startUtc, endUtcExclusive, normFrom, normTo);
    }

    public static string FormatJsonPretty(string? rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            return JsonSerializer.Serialize(doc.RootElement, PrettyJsonOptions);
        }
        catch (JsonException)
        {
            return rawJson;
        }
    }

    public static string FormatLocalDateTime(DateTime utcTimestamp, string format = "yyyy-MM-dd HH:mm") =>
        DateTime.SpecifyKind(utcTimestamp, DateTimeKind.Utc)
            .ToLocalTime()
            .ToString(format, CultureInfo.InvariantCulture);

    private static DateTime ConvertLocalStartOfDayToUtc(DateOnly date, TimeZoneInfo tz)
    {
        var unspecified = date.ToDateTime(TimeOnly.MinValue, DateTimeKind.Unspecified);
        if (tz.IsInvalidTime(unspecified))
        {
            // DST spring-forward gap at midnight: advance 1 hour so TimeZoneInfo.ConvertTimeToUtc succeeds.
            unspecified = unspecified.AddHours(1);
        }

        var offset = tz.GetUtcOffset(unspecified);
        return new DateTimeOffset(unspecified, offset).UtcDateTime;
    }

    private static bool IsPriorAudit(ComputerAudit candidate, int currentId, DateTime? currentTime)
    {
        if (!currentTime.HasValue)
            return candidate.Id < currentId;

        var candidateTime = candidate.FinishedAt ?? candidate.StartedAt;
        if (!candidateTime.HasValue)
            return candidate.Id < currentId;

        if (candidateTime.Value < currentTime.Value)
            return true;

        return candidateTime.Value == currentTime.Value && candidate.Id < currentId;
    }

    private static int ResolveSortOrder(CheckResult result, IReadOnlyDictionary<int, int>? sortOrderByDefinitionId)
    {
        if (sortOrderByDefinitionId is not null &&
            sortOrderByDefinitionId.TryGetValue(result.CheckDefinitionId, out var mappedOrder))
        {
            return mappedOrder;
        }

        if (result.CheckDefinition is not null)
        {
            return result.CheckDefinition.SortOrder;
        }

        return int.MaxValue;
    }

    private static List<CheckResult> SortComparisonItems(List<CheckResult> items) =>
        items
            .OrderByDescending(r => r.RiskLevel)
            .ThenBy(r => GetCategoryOrder(r.Category))
            .ThenBy(r => r.Code, StringComparer.OrdinalIgnoreCase)
            .ToList();
}

