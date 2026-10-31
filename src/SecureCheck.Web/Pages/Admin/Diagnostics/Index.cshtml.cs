using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Admin.Diagnostics;

[Authorize(Policy = AppPolicies.Manage)]
public class IndexModel : PageModel
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly ApplicationDbContext _db;
    private readonly PowerShellRunner _runner;
    private readonly AuditEvaluator _evaluator;
    private readonly ActivityLogService _activityLog;

    public IndexModel(
        ApplicationDbContext db,
        PowerShellRunner runner,
        AuditEvaluator evaluator,
        ActivityLogService activityLog)
    {
        _db = db;
        _runner = runner;
        _evaluator = evaluator;
        _activityLog = activityLog;
    }

    public IReadOnlyList<Computer> Computers { get; private set; } = Array.Empty<Computer>();

    [BindProperty]
    public int? SelectedComputerId { get; set; }

    [BindProperty]
    public string? RawJson { get; set; }

    public Computer? ExecutedComputer { get; private set; }
    public ExecutionMode? ExecutedMode { get; private set; }
    public TimeSpan? Duration { get; private set; }
    public string? PrettyJson { get; private set; }
    public AuditFacts? ParsedFacts { get; private set; }
    public EvaluationResult? Evaluation { get; private set; }
    public string ScoreLabel { get; private set; } = "Not Evaluated";
    public string ScoreBadgeClass { get; private set; } = "status-error";
    public string ScoreTextClass { get; private set; } = "text-sc-gray";
    public RunnerErrorKind? ErrorKind { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(int? computerId = null)
    {
        await LoadComputersAsync();
        SelectedComputerId = computerId ?? Computers.FirstOrDefault()?.Id;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        await LoadComputersAsync();
        await ExecuteScriptForSelectionAsync(evaluateAfterRun: false);
        return Page();
    }

    public async Task<IActionResult> OnPostRunAndEvaluateAsync()
    {
        await LoadComputersAsync();
        await ExecuteScriptForSelectionAsync(evaluateAfterRun: true);
        return Page();
    }

    public async Task<IActionResult> OnPostEvaluateAsync()
    {
        await LoadComputersAsync();

        // If raw JSON was already collected on the page, evaluate it directly without re-running PowerShell.
        if (!string.IsNullOrWhiteSpace(RawJson))
        {
            if (SelectedComputerId.HasValue)
            {
                ExecutedComputer = Computers.FirstOrDefault(c => c.Id == SelectedComputerId.Value);
                if (ExecutedComputer is not null)
                {
                    ExecutedMode = PowerShellRunner.DetermineMode(ExecutedComputer.HostName);
                }
            }

            var enabledChecks = await ApplyEnabledChecklistOrder(_db.CheckDefinitions.AsNoTracking())
                .ToListAsync(HttpContext.RequestAborted);
            var settings = await LoadSettingsDictionaryAsync(HttpContext.RequestAborted);

            if (TryEvaluatePayload(RawJson, enabledChecks, settings, DateTimeOffset.UtcNow))
            {
                var targetLabel = ExecutedComputer is not null
                    ? $"{ExecutedComputer.Name} ({ExecutedComputer.HostName})"
                    : (ParsedFacts?.ComputerName ?? "JSON Payload");
                var scoreText = Evaluation?.Score?.ToString(CultureInfo.InvariantCulture) ?? "N/A";

                await _activityLog.LogAsync(
                    User.Identity?.Name,
                    "Evaluated Diagnostics Payload",
                    $"{targetLabel}: Score {scoreText} ({Evaluation?.Passed ?? 0} pass, {Evaluation?.Failed ?? 0} fail, {Evaluation?.Errors ?? 0} error)");
            }

            return Page();
        }

        await ExecuteScriptForSelectionAsync(evaluateAfterRun: true);
        return Page();
    }

    internal static IQueryable<CheckDefinition> ApplyEnabledChecklistOrder(IQueryable<CheckDefinition> query) =>
        query.Where(c => c.IsEnabled)
             .OrderBy(c => c.SortOrder)
             .ThenBy(c => c.Id);

    internal bool TryEvaluatePayload(
        string rawJson,
        IReadOnlyList<CheckDefinition> enabledChecks,
        IReadOnlyDictionary<string, string> settings,
        DateTimeOffset utcNow)
    {
        RawJson = rawJson;
        PrettyJson = FormatJsonPretty(rawJson);

        if (!AuditFacts.TryParse(rawJson, out var facts, out var parseError))
        {
            ErrorMessage = parseError;
            return false;
        }

        ParsedFacts = facts;

        // Simulated demo fixtures have fixed historical dates; use their snapshot timestamp so demo:secure stays green.
        // Live Local and Remote scans always evaluate against the current server clock.
        var evaluationNow = ExecutedMode == ExecutionMode.Demo && facts.CollectedAt.HasValue
            ? facts.CollectedAt.Value
            : utcNow;

        Evaluation = _evaluator.Evaluate(facts, enabledChecks, evaluationNow);

        var goodMin = ParseSettingInt(settings, AppSettingKeys.ScoreGoodMin, 90);
        var fairMin = ParseSettingInt(settings, AppSettingKeys.ScoreFairMin, 70);
        var poorMin = ParseSettingInt(settings, AppSettingKeys.ScorePoorMin, 50);
        (ScoreLabel, ScoreBadgeClass, ScoreTextClass) =
            AuditEvaluator.DescribeScore(Evaluation.Score, goodMin, fairMin, poorMin);

        return true;
    }

    public static string FormatJsonPretty(string rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            return JsonSerializer.Serialize(doc.RootElement, IndentedJsonOptions);
        }
        catch (JsonException)
        {
            return rawJson;
        }
    }

    private async Task ExecuteScriptForSelectionAsync(bool evaluateAfterRun)
    {
        RawJson = null;

        if (!SelectedComputerId.HasValue)
        {
            ErrorMessage = "Select a computer before running the audit script.";
            return;
        }

        var computer = Computers.FirstOrDefault(c => c.Id == SelectedComputerId.Value);
        if (computer is null)
        {
            ErrorMessage = "The selected computer could not be found.";
            return;
        }

        ExecutedComputer = computer;
        ExecutedMode = PowerShellRunner.DetermineMode(computer.HostName);

        var result = await _runner.RunAuditAsync(computer, HttpContext.RequestAborted);
        Duration = result.Duration;

        if (!result.Success || string.IsNullOrWhiteSpace(result.Json))
        {
            ErrorKind = result.ErrorKind;
            ErrorMessage = result.ErrorMessage ?? "Audit script execution failed.";
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Ran Diagnostics Script",
                $"{computer.Name} ({computer.HostName}): Failed ({result.ErrorKind}) — {ErrorMessage}");
            return;
        }

        RawJson = result.Json;
        PrettyJson = FormatJsonPretty(result.Json);

        if (!evaluateAfterRun)
        {
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Ran Diagnostics Script",
                $"{computer.Name} ({computer.HostName}): Succeeded in {result.Duration.TotalSeconds:F2}s");
            return;
        }

        var enabledChecks = await ApplyEnabledChecklistOrder(_db.CheckDefinitions.AsNoTracking())
            .ToListAsync(HttpContext.RequestAborted);
        var settings = await LoadSettingsDictionaryAsync(HttpContext.RequestAborted);

        if (TryEvaluatePayload(result.Json, enabledChecks, settings, DateTimeOffset.UtcNow))
        {
            var scoreText = Evaluation?.Score?.ToString(CultureInfo.InvariantCulture) ?? "N/A";
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Evaluated Diagnostics Script",
                $"{computer.Name} ({computer.HostName}): Score {scoreText} ({Evaluation?.Passed ?? 0} pass, {Evaluation?.Failed ?? 0} fail, {Evaluation?.Errors ?? 0} error) in {result.Duration.TotalSeconds:F2}s");
        }
    }

    private async Task LoadComputersAsync()
    {
        Computers = await _db.Computers
            .AsNoTracking()
            .OrderByDescending(c => c.IsActive)
            .ThenBy(c => c.Name)
            .ToListAsync();
    }

    private async Task<Dictionary<string, string>> LoadSettingsDictionaryAsync(CancellationToken ct)
    {
        var rows = await _db.AppSettings.AsNoTracking().ToListAsync(ct);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            map[row.Key] = row.Value;
        }
        return map;
    }

    private static int ParseSettingInt(IReadOnlyDictionary<string, string> settings, string key, int fallback) =>
        settings.TryGetValue(key, out var raw) && int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : fallback;
}
