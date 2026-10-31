using System.Globalization;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>
/// Creates High and Critical risk alerts when a ComputerAudit completes with serious findings.
/// </summary>
public sealed class AlertService
{
    private const int MaxAlertMessageLength = 500;

    private readonly ApplicationDbContext _db;

    public AlertService(ApplicationDbContext db)
    {
        _db = db;
    }

    /// <summary>
    /// Stages an Alert entity on the current DbContext if the completed audit has High or Critical overall risk.
    /// Caller saves changes as part of the ComputerAudit unit of work.
    /// </summary>
    public Alert? StageAlertIfNeeded(
        ComputerAudit computerAudit,
        string? computerName,
        IEnumerable<CheckResult> checkResults,
        DateTime? createdAtUtc = null)
    {
        var alert = BuildAlertIfNeeded(computerAudit, computerName, checkResults, createdAtUtc);
        if (alert is not null)
        {
            _db.Alerts.Add(alert);
        }

        return alert;
    }

    /// <summary>
    /// Creates and immediately persists an Alert row if the completed audit has High or Critical overall risk.
    /// </summary>
    public async Task<Alert?> CreateAlertIfNeededAsync(
        ComputerAudit computerAudit,
        string? computerName,
        IEnumerable<CheckResult> checkResults,
        CancellationToken ct = default)
    {
        var alert = StageAlertIfNeeded(computerAudit, computerName, checkResults);
        if (alert is not null)
        {
            await _db.SaveChangesAsync(ct);
        }

        return alert;
    }

    /// <summary>
    /// Pure builder for unit testing and transactional staging: returns an Alert only when a Completed
    /// ComputerAudit has OverallRisk High or Critical; returns null for Low, Medium, Secure (null), or failed runs.
    /// </summary>
    public static Alert? BuildAlertIfNeeded(
        ComputerAudit computerAudit,
        string? computerName,
        IEnumerable<CheckResult> checkResults,
        DateTime? createdAtUtc = null)
    {
        ArgumentNullException.ThrowIfNull(computerAudit);
        ArgumentNullException.ThrowIfNull(checkResults);

        if (computerAudit.Status != ComputerAuditStatus.Completed)
            return null;

        if (computerAudit.OverallRisk is not (RiskLevel.High or RiskLevel.Critical))
            return null;

        var severity = computerAudit.OverallRisk.Value;
        var displayName = string.IsNullOrWhiteSpace(computerName)
            ? $"Computer #{computerAudit.ComputerId}"
            : computerName.Trim();

        var message = FormatAlertMessage(displayName, severity, computerAudit.Score, checkResults);

        return new Alert
        {
            ComputerId = computerAudit.ComputerId,
            ComputerAuditId = computerAudit.Id,
            Severity = severity,
            Message = Truncate(message, MaxAlertMessageLength),
            CreatedAt = createdAtUtc ?? DateTime.UtcNow,
            IsAcknowledged = false
        };
    }

    /// <summary>
    /// Formats a summary message such as "SC-LAB-01: 2 Critical and 2 High findings (score 50)".
    /// </summary>
    public static string FormatAlertMessage(
        string computerName,
        RiskLevel overallRisk,
        int? score,
        IEnumerable<CheckResult> checkResults)
    {
        ArgumentNullException.ThrowIfNull(checkResults);

        var criticalCount = 0;
        var highCount = 0;

        foreach (var result in checkResults)
        {
            if (result is null || result.Status != CheckStatus.Fail)
                continue;

            if (result.RiskLevel == RiskLevel.Critical)
                criticalCount++;
            else if (result.RiskLevel == RiskLevel.High)
                highCount++;
        }

        string findingsPart;
        if (criticalCount > 0 && highCount > 0)
        {
            findingsPart = $"{criticalCount} Critical and {highCount} High findings";
        }
        else if (criticalCount > 0)
        {
            findingsPart = $"{criticalCount} Critical {(criticalCount == 1 ? "finding" : "findings")}";
        }
        else if (highCount > 0)
        {
            findingsPart = $"{highCount} High {(highCount == 1 ? "finding" : "findings")}";
        }
        else
        {
            findingsPart = $"{overallRisk} risk findings";
        }

        var scorePart = score.HasValue
            ? $"score {score.Value.ToString(CultureInfo.InvariantCulture)}"
            : "score N/A";

        var trimmedName = string.IsNullOrWhiteSpace(computerName) ? "Unknown Computer" : computerName.Trim();
        return $"{trimmedName}: {findingsPart} ({scorePart})";
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..(maxLength - 3)] + "...";
}

