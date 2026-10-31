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
/// Live progress view and JSON polling endpoint for an AuditRun (/Audits/Progress/{runId:int}).
/// Accessible to all authenticated users (Administrator, Auditor, Viewer) via FallbackPolicy.
/// </summary>
public class ProgressModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _authorizationService;

    public ProgressModel(
        ApplicationDbContext db,
        IAuthorizationService authorizationService)
    {
        _db = db;
        _authorizationService = authorizationService;
    }

    [TempData]
    public string? SkippedMessage { get; set; }

    public AuditRunProgressDto Snapshot { get; private set; } = null!;
    public bool CanAudit { get; private set; }

    public async Task<IActionResult> OnGetAsync(int runId)
    {
        CanAudit = (await _authorizationService.AuthorizeAsync(User, AppPolicies.Audit)).Succeeded;

        var snapshot = await BuildProgressSnapshotAsync(runId, HttpContext.RequestAborted);
        if (snapshot is null)
            return NotFound();

        Snapshot = snapshot;
        return Page();
    }

    public async Task<IActionResult> OnGetStatusAsync(int runId)
    {
        var snapshot = await BuildProgressSnapshotAsync(runId, HttpContext.RequestAborted);
        if (snapshot is null)
            return NotFound();

        return new JsonResult(snapshot);
    }

    private async Task<AuditRunProgressDto?> BuildProgressSnapshotAsync(int runId, CancellationToken ct)
    {
        var run = await _db.AuditRuns
            .AsNoTracking()
            .Include(r => r.ComputerAudits)
                .ThenInclude(ca => ca.Computer)
            .FirstOrDefaultAsync(r => r.Id == runId, ct);

        if (run is null)
            return null;

        var settings = await _db.AppSettings
            .AsNoTracking()
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);

        var goodMin = ParseSettingInt(settings, AppSettingKeys.ScoreGoodMin, 90);
        var fairMin = ParseSettingInt(settings, AppSettingKeys.ScoreFairMin, 70);
        var poorMin = ParseSettingInt(settings, AppSettingKeys.ScorePoorMin, 50);

        return MapSnapshot(run, goodMin, fairMin, poorMin);
    }

    public static AuditRunProgressDto MapSnapshot(
        AuditRun run,
        int goodMin = 90,
        int fairMin = 70,
        int poorMin = 50)
    {
        ArgumentNullException.ThrowIfNull(run);

        var isFinished = run.Status is AuditRunStatus.Completed or AuditRunStatus.CompletedWithErrors;
        var clampedCompleted = run.TotalComputers > 0
            ? Math.Clamp(run.CompletedComputers, 0, run.TotalComputers)
            : 0;

        int percentComplete;
        if (run.TotalComputers <= 0)
        {
            percentComplete = isFinished ? 100 : 0;
        }
        else if (isFinished)
        {
            percentComplete = 100;
        }
        else
        {
            percentComplete = (int)Math.Round(
                100.0 * clampedCompleted / run.TotalComputers,
                MidpointRounding.AwayFromZero);
        }

        var computers = run.ComputerAudits
            .OrderBy(ca => ca.Computer?.Name ?? string.Empty)
            .ThenBy(ca => ca.Id)
            .Select(ca => MapComputerRow(ca, goodMin, fairMin, poorMin))
            .ToList();

        return new AuditRunProgressDto
        {
            RunId = run.Id,
            StartedByName = run.StartedByName,
            Status = run.Status.ToString(),
            StatusDisplay = run.Status.ToDisplayName(),
            StatusBadgeClass = run.Status.ToBadgeClass(),
            IsFinished = isFinished,
            TotalComputers = run.TotalComputers,
            CompletedComputers = clampedCompleted,
            PercentComplete = percentComplete,
            CreatedAtLocal = FormatLocalTimestamp(run.CreatedAt),
            StartedAtLocal = run.StartedAt.HasValue ? FormatLocalTimestamp(run.StartedAt.Value) : null,
            FinishedAtLocal = run.FinishedAt.HasValue ? FormatLocalTimestamp(run.FinishedAt.Value) : null,
            Computers = computers
        };
    }

    private static ComputerAuditProgressDto MapComputerRow(
        ComputerAudit ca,
        int goodMin,
        int fairMin,
        int poorMin)
    {
        var computerName = ca.Computer?.Name ?? $"Computer #{ca.ComputerId}";
        var hostName = ca.Computer?.HostName ?? string.Empty;
        var location = ca.Computer?.Location ?? string.Empty;
        var execMode = PowerShellRunner.DetermineMode(hostName);

        var (scoreLabel, scoreBadgeClass, scoreTextClass) =
            AuditEvaluator.DescribeScore(ca.Score, goodMin, fairMin, poorMin);

        var overallRiskDisplay = "—";
        var overallRiskBadgeClass = string.Empty;

        if (ca.Status == ComputerAuditStatus.Completed)
        {
            if (ca.OverallRisk.HasValue)
            {
                overallRiskDisplay = ca.OverallRisk.Value.ToString();
                overallRiskBadgeClass = ca.OverallRisk.Value.ToBadgeClass();
            }
            else if (ca.Score.HasValue)
            {
                overallRiskDisplay = "Secure";
                overallRiskBadgeClass = "risk-low";
            }
            else
            {
                overallRiskDisplay = "Not Evaluated";
                overallRiskBadgeClass = "status-error";
            }
        }

        return new ComputerAuditProgressDto
        {
            ComputerAuditId = ca.Id,
            ComputerId = ca.ComputerId,
            ComputerName = computerName,
            HostName = hostName,
            Location = location,
            ExecutionModeDisplay = execMode.ToDisplayName(),
            ExecutionModeIcon = execMode.ToIconClass(),
            Status = ca.Status.ToString(),
            StatusDisplay = ca.Status.ToDisplayName(),
            StatusBadgeClass = ca.Status.ToBadgeClass(),
            IsRunning = ca.Status == ComputerAuditStatus.Running,
            Score = ca.Score,
            ScoreLabel = scoreLabel,
            ScoreBadgeClass = scoreBadgeClass,
            ScoreTextClass = scoreTextClass,
            OverallRiskDisplay = overallRiskDisplay,
            OverallRiskBadgeClass = overallRiskBadgeClass,
            HasCounts = ca.Status == ComputerAuditStatus.Completed,
            PassedCount = ca.PassedCount,
            FailedCount = ca.FailedCount,
            ErrorCount = ca.ErrorCount,
            OsCaption = ca.OsCaption,
            ErrorMessage = ca.ErrorMessage
        };
    }

    private static string FormatLocalTimestamp(DateTime utcTimestamp) =>
        DateTime.SpecifyKind(utcTimestamp, DateTimeKind.Utc)
            .ToLocalTime()
            .ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static int ParseSettingInt(IReadOnlyDictionary<string, string> settings, string key, int fallback) =>
        settings.TryGetValue(key, out var raw) &&
        int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : fallback;
}

public sealed class AuditRunProgressDto
{
    public int RunId { get; init; }
    public string StartedByName { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public string StatusDisplay { get; init; } = string.Empty;
    public string StatusBadgeClass { get; init; } = string.Empty;
    public bool IsFinished { get; init; }
    public int TotalComputers { get; init; }
    public int CompletedComputers { get; init; }
    public int PercentComplete { get; init; }
    public string CreatedAtLocal { get; init; } = string.Empty;
    public string? StartedAtLocal { get; init; }
    public string? FinishedAtLocal { get; init; }
    public IReadOnlyList<ComputerAuditProgressDto> Computers { get; init; } = Array.Empty<ComputerAuditProgressDto>();
}

public sealed class ComputerAuditProgressDto
{
    public int ComputerAuditId { get; init; }
    public int ComputerId { get; init; }
    public string ComputerName { get; init; } = string.Empty;
    public string HostName { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public string ExecutionModeDisplay { get; init; } = string.Empty;
    public string ExecutionModeIcon { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public string StatusDisplay { get; init; } = string.Empty;
    public string StatusBadgeClass { get; init; } = string.Empty;
    public bool IsRunning { get; init; }
    public int? Score { get; init; }
    public string ScoreLabel { get; init; } = string.Empty;
    public string ScoreBadgeClass { get; init; } = string.Empty;
    public string ScoreTextClass { get; init; } = string.Empty;
    public string OverallRiskDisplay { get; init; } = string.Empty;
    public string OverallRiskBadgeClass { get; init; } = string.Empty;
    public bool HasCounts { get; init; }
    public int PassedCount { get; init; }
    public int FailedCount { get; init; }
    public int ErrorCount { get; init; }
    public string? OsCaption { get; init; }
    public string? ErrorMessage { get; init; }
}

