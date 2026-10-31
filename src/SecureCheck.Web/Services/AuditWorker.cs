using System.Globalization;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>
/// Background worker that recovers orphaned runs on startup, consumes AuditRun IDs from AuditQueue,
/// and audits target computers in parallel (throttled by MaxParallelAudits) using an isolated DbContext per computer.
/// </summary>
public sealed class AuditWorker : BackgroundService
{
    public const int DefaultMaxParallelAudits = 5;
    public const int MaxAllowedParallelAudits = 50;
    public const string InterruptedErrorMessage = "Interrupted — app restarted";

    private readonly AuditQueue _queue;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly PowerShellRunner _runner;
    private readonly AuditEvaluator _evaluator;
    private readonly ILogger<AuditWorker> _logger;

    public AuditWorker(
        AuditQueue queue,
        IServiceScopeFactory scopeFactory,
        PowerShellRunner runner,
        AuditEvaluator evaluator,
        ILogger<AuditWorker> logger)
    {
        _queue = queue;
        _scopeFactory = scopeFactory;
        _runner = runner;
        _evaluator = evaluator;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RecoverInterruptedRunsAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to recover interrupted audit runs during startup.");
        }

        await foreach (var runId in _queue.ReadAllAsync(stoppingToken))
        {
            try
            {
                await ProcessRunAsync(runId, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled error while processing audit run #{RunId}.", runId);
                await TryMarkRunFailedSafeAsync(runId, stoppingToken);
            }
        }
    }

    /// <summary>
    /// Marks any AuditRun rows left in Queued or Running from a prior crash/restart as CompletedWithErrors
    /// and sets their Pending/Running ComputerAudit rows to Failed ("Interrupted — app restarted").
    /// </summary>
    internal async Task<int> RecoverInterruptedRunsAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var orphanedRuns = await db.AuditRuns
            .Include(r => r.ComputerAudits)
            .Where(r => r.Status == AuditRunStatus.Queued || r.Status == AuditRunStatus.Running)
            .ToListAsync(ct);

        if (orphanedRuns.Count == 0)
            return 0;

        var recoveredCount = ApplyCrashRecovery(orphanedRuns, DateTime.UtcNow);
        if (recoveredCount > 0)
        {
            await db.SaveChangesAsync(ct);
            _logger.LogWarning("Recovered {Count} interrupted audit run(s) left over from a previous session.", recoveredCount);
        }

        return recoveredCount;
    }

    private async Task ProcessRunAsync(int runId, CancellationToken stoppingToken)
    {
        List<int> computerAuditIds;
        int maxParallel;

        // Scope 1: Transition AuditRun to Running, record StartedAt, and read MaxParallelAudits.
        using (var initScope = _scopeFactory.CreateScope())
        {
            var db = initScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var run = await db.AuditRuns
                .Include(r => r.ComputerAudits)
                .FirstOrDefaultAsync(r => r.Id == runId, stoppingToken);

            if (run is null)
            {
                _logger.LogWarning("Dequeued audit run #{RunId}, but no matching row exists.", runId);
                return;
            }

            if (run.Status is AuditRunStatus.Completed or AuditRunStatus.CompletedWithErrors)
            {
                _logger.LogInformation("Skipping audit run #{RunId} because it is already {Status}.", runId, run.Status);
                return;
            }

            run.Status = AuditRunStatus.Running;
            run.StartedAt ??= DateTime.UtcNow;

            var settings = await db.AppSettings
                .AsNoTracking()
                .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, stoppingToken);

            maxParallel = ResolveMaxParallelAudits(settings);

            computerAuditIds = run.ComputerAudits
                .Where(ca => ca.Status == ComputerAuditStatus.Pending)
                .Select(ca => ca.Id)
                .ToList();

            await db.SaveChangesAsync(stoppingToken);
        }

        _logger.LogInformation(
            "Starting audit run #{RunId} across {Count} computer(s) (MaxParallelAudits = {MaxParallel}).",
            runId,
            computerAuditIds.Count,
            maxParallel);

        // Execute computers in parallel throttled by SemaphoreSlim, with an isolated DI scope / DbContext per computer.
        if (computerAuditIds.Count > 0)
        {
            using var semaphore = new SemaphoreSlim(maxParallel, maxParallel);
            var tasks = computerAuditIds.Select(caId =>
                AuditComputerThrottledAsync(runId, caId, semaphore, stoppingToken));

            await Task.WhenAll(tasks);
        }

        // Final scope: Set FinishedAt and final AuditRunStatus (Completed vs CompletedWithErrors).
        using (var finalizeScope = _scopeFactory.CreateScope())
        {
            var db = finalizeScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var run = await db.AuditRuns.FirstOrDefaultAsync(r => r.Id == runId, stoppingToken);
            if (run is null)
                return;

            var statuses = await db.ComputerAudits
                .AsNoTracking()
                .Where(ca => ca.AuditRunId == runId)
                .Select(ca => ca.Status)
                .ToListAsync(stoppingToken);

            run.CompletedComputers = statuses.Count(IsTerminalComputerStatus);
            run.Status = DetermineFinalRunStatus(statuses);
            run.FinishedAt = DateTime.UtcNow;

            await db.SaveChangesAsync(stoppingToken);

            _logger.LogInformation(
                "Finished audit run #{RunId} with status {Status} ({Completed}/{Total} computers).",
                runId,
                run.Status,
                run.CompletedComputers,
                run.TotalComputers);
        }
    }

    private async Task AuditComputerThrottledAsync(
        int runId,
        int computerAuditId,
        SemaphoreSlim semaphore,
        CancellationToken stoppingToken)
    {
        await semaphore.WaitAsync(stoppingToken);
        try
        {
            await AuditSingleComputerAsync(runId, computerAuditId, stoppingToken);
        }
        finally
        {
            semaphore.Release();
        }
    }

    private async Task AuditSingleComputerAsync(
        int runId,
        int computerAuditId,
        CancellationToken stoppingToken)
    {
        var incrementedProgress = false;

        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var alertService = scope.ServiceProvider.GetRequiredService<AlertService>();

            var computerAudit = await db.ComputerAudits
                .Include(ca => ca.Computer)
                .FirstOrDefaultAsync(ca => ca.Id == computerAuditId, stoppingToken);

            if (computerAudit is null)
                return;

            computerAudit.Status = ComputerAuditStatus.Running;
            computerAudit.StartedAt = DateTime.UtcNow;
            await db.SaveChangesAsync(stoppingToken);

            var runnerResult = await _runner.RunAuditAsync(computerAudit.Computer, stoppingToken);
            var now = DateTimeOffset.UtcNow;

            if (!runnerResult.Success || string.IsNullOrWhiteSpace(runnerResult.Json))
            {
                ApplyRunnerFailure(
                    computerAudit,
                    runnerResult.ErrorKind,
                    runnerResult.ErrorMessage,
                    now.UtcDateTime);
            }
            else
            {
                var enabledChecks = await db.CheckDefinitions
                    .AsNoTracking()
                    .Where(c => c.IsEnabled)
                    .OrderBy(c => c.SortOrder)
                    .ThenBy(c => c.Id)
                    .ToListAsync(stoppingToken);

                var checkResults = ApplySuccessfulRunJson(
                    computerAudit,
                    computerAudit.Computer,
                    runnerResult.Json,
                    enabledChecks,
                    _evaluator,
                    now);

                if (checkResults.Count > 0)
                {
                    db.CheckResults.AddRange(checkResults);
                }

                if (computerAudit.Status == ComputerAuditStatus.Completed)
                {
                    alertService.StageAlertIfNeeded(
                        computerAudit,
                        computerAudit.Computer.Name,
                        checkResults,
                        now.UtcDateTime);
                }
            }

            await db.SaveChangesAsync(stoppingToken);

            await IncrementCompletedComputersAsync(db, runId, stoppingToken);
            incrementedProgress = true;
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Unexpected exception while auditing ComputerAudit #{ComputerAuditId} in run #{RunId}.",
                computerAuditId,
                runId);

            await TryRecoverSingleComputerExceptionAsync(runId, computerAuditId, incrementedProgress, stoppingToken);
        }
    }

    private static Task IncrementCompletedComputersAsync(
        ApplicationDbContext db,
        int runId,
        CancellationToken ct) =>
        db.AuditRuns
            .Where(r => r.Id == runId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(r => r.CompletedComputers, r => r.CompletedComputers + 1),
                ct);

    private async Task TryRecoverSingleComputerExceptionAsync(
        int runId,
        int computerAuditId,
        bool alreadyIncremented,
        CancellationToken ct)
    {
        try
        {
            using var fallbackScope = _scopeFactory.CreateScope();
            var db = fallbackScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var computerAudit = await db.ComputerAudits.FirstOrDefaultAsync(ca => ca.Id == computerAuditId, ct);
            if (computerAudit is not null && !IsTerminalComputerStatus(computerAudit.Status))
            {
                computerAudit.Status = ComputerAuditStatus.Failed;
                computerAudit.ErrorMessage = "An unexpected internal error occurred while saving audit results.";
                computerAudit.FinishedAt = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
            }

            if (!alreadyIncremented)
            {
                await IncrementCompletedComputersAsync(db, runId, ct);
            }
        }
        catch (Exception fallbackEx) when (fallbackEx is not OperationCanceledException)
        {
            _logger.LogError(
                fallbackEx,
                "Failed to record fallback failure state for ComputerAudit #{ComputerAuditId}.",
                computerAuditId);
        }
    }

    private async Task TryMarkRunFailedSafeAsync(int runId, CancellationToken ct)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var run = await db.AuditRuns
                .Include(r => r.ComputerAudits)
                .FirstOrDefaultAsync(r => r.Id == runId, ct);

            if (run is null || run.Status is AuditRunStatus.Completed or AuditRunStatus.CompletedWithErrors)
                return;

            var nowUtc = DateTime.UtcNow;
            foreach (var ca in run.ComputerAudits.Where(c => !IsTerminalComputerStatus(c.Status)))
            {
                ca.Status = ComputerAuditStatus.Failed;
                ca.ErrorMessage ??= "Audit run encountered an unexpected worker error.";
                ca.FinishedAt = nowUtc;
            }

            run.CompletedComputers = run.ComputerAudits.Count(c => IsTerminalComputerStatus(c.Status));
            run.Status = AuditRunStatus.CompletedWithErrors;
            run.FinishedAt = nowUtc;

            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Could not mark failed status on audit run #{RunId}.", runId);
        }
    }

    // ---------- Pure / Testable Domain Logic ----------

    /// <summary>
    /// Maps RunnerErrorKind to ComputerAuditStatus:
    /// Unreachable, AccessDenied, NotTrusted, Timeout -> Unreachable; Other (or null) -> Failed.
    /// </summary>
    public static ComputerAuditStatus MapFailureStatus(RunnerErrorKind? errorKind) => errorKind switch
    {
        RunnerErrorKind.Unreachable => ComputerAuditStatus.Unreachable,
        RunnerErrorKind.AccessDenied => ComputerAuditStatus.Unreachable,
        RunnerErrorKind.NotTrusted => ComputerAuditStatus.Unreachable,
        RunnerErrorKind.Timeout => ComputerAuditStatus.Unreachable,
        _ => ComputerAuditStatus.Failed
    };

    /// <summary>
    /// Determines the final AuditRunStatus when all computer tasks finish:
    /// CompletedWithErrors if any computer ended in Unreachable or Failed (or non-Completed); otherwise Completed.
    /// </summary>
    public static AuditRunStatus DetermineFinalRunStatus(IEnumerable<ComputerAuditStatus> statuses)
    {
        ArgumentNullException.ThrowIfNull(statuses);
        return statuses.Any(s => s != ComputerAuditStatus.Completed)
            ? AuditRunStatus.CompletedWithErrors
            : AuditRunStatus.Completed;
    }

    /// <summary>
    /// Reads MaxParallelAudits from AppSettings (default 5, clamped between 1 and 50).
    /// </summary>
    public static int ResolveMaxParallelAudits(IReadOnlyDictionary<string, string>? settings)
    {
        if (settings is not null &&
            settings.TryGetValue(AppSettingKeys.MaxParallelAudits, out var raw) &&
            int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) &&
            parsed > 0)
        {
            return Math.Min(parsed, MaxAllowedParallelAudits);
        }

        return DefaultMaxParallelAudits;
    }

    /// <summary>
    /// Uses facts.CollectedAt for simulated Demo endpoints so historical fixture timestamps stay deterministic,
    /// while Local and Remote scans always evaluate against the current UTC server clock.
    /// </summary>
    public static DateTimeOffset SelectEvaluationClock(
        string? hostName,
        AuditFacts facts,
        DateTimeOffset utcNow)
    {
        ArgumentNullException.ThrowIfNull(facts);

        return PowerShellRunner.DetermineMode(hostName) == ExecutionMode.Demo && facts.CollectedAt.HasValue
            ? facts.CollectedAt.Value
            : utcNow;
    }

    /// <summary>
    /// Applies startup crash recovery in-place to orphaned Queued/Running AuditRuns and their Pending/Running ComputerAudits.
    /// </summary>
    public static int ApplyCrashRecovery(IEnumerable<AuditRun> runs, DateTime finishedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(runs);

        var recovered = 0;
        foreach (var run in runs)
        {
            if (run.Status is not (AuditRunStatus.Queued or AuditRunStatus.Running))
                continue;

            run.Status = AuditRunStatus.CompletedWithErrors;
            run.FinishedAt = finishedAtUtc;

            foreach (var ca in run.ComputerAudits)
            {
                if (ca.Status is ComputerAuditStatus.Pending or ComputerAuditStatus.Running)
                {
                    ca.Status = ComputerAuditStatus.Failed;
                    ca.ErrorMessage = InterruptedErrorMessage;
                    ca.FinishedAt = finishedAtUtc;
                }
            }

            if (run.ComputerAudits.Count > 0)
            {
                run.CompletedComputers = run.ComputerAudits.Count(ca => IsTerminalComputerStatus(ca.Status));
            }

            recovered++;
        }

        return recovered;
    }

    /// <summary>
    /// Populates failure fields on a ComputerAudit after PowerShellRunner fails.
    /// </summary>
    public static void ApplyRunnerFailure(
        ComputerAudit computerAudit,
        RunnerErrorKind? errorKind,
        string? errorMessage,
        DateTime finishedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(computerAudit);

        computerAudit.Status = MapFailureStatus(errorKind);
        computerAudit.ErrorMessage = TruncateNullable(
            string.IsNullOrWhiteSpace(errorMessage) ? "Audit script execution failed." : errorMessage.Trim(),
            1000);
        computerAudit.FinishedAt = finishedAtUtc;
    }

    /// <summary>
    /// Parses collected JSON with AuditFacts.TryParse, evaluates enabled checks, populates ComputerAudit + Computer.Last*,
    /// and returns CheckResult snapshot rows (or marks ComputerAudit.Failed on invalid JSON).
    /// </summary>
    public static List<CheckResult> ApplySuccessfulRunJson(
        ComputerAudit computerAudit,
        Computer computer,
        string? rawJson,
        IReadOnlyList<CheckDefinition> enabledChecks,
        AuditEvaluator evaluator,
        DateTimeOffset utcNow)
    {
        ArgumentNullException.ThrowIfNull(computerAudit);
        ArgumentNullException.ThrowIfNull(computer);
        ArgumentNullException.ThrowIfNull(enabledChecks);
        ArgumentNullException.ThrowIfNull(evaluator);

        computerAudit.RawJson = rawJson;

        if (!AuditFacts.TryParse(rawJson, out var facts, out var parseError))
        {
            computerAudit.Status = ComputerAuditStatus.Failed;
            computerAudit.ErrorMessage = TruncateNullable(parseError ?? "Invalid audit JSON payload.", 1000);
            computerAudit.FinishedAt = utcNow.UtcDateTime;
            return new List<CheckResult>();
        }

        var evaluationNow = SelectEvaluationClock(computer.HostName, facts, utcNow);
        var evaluation = evaluator.Evaluate(facts, enabledChecks, evaluationNow);

        var checkResults = new List<CheckResult>(evaluation.Outcomes.Count);
        foreach (var outcome in evaluation.Outcomes)
        {
            checkResults.Add(new CheckResult
            {
                ComputerAuditId = computerAudit.Id,
                CheckDefinitionId = outcome.CheckDefinitionId,
                Code = TruncateRequired(outcome.Code, 40),
                Name = TruncateRequired(outcome.Name, 150),
                Category = outcome.Category,
                RiskLevel = outcome.RiskLevel,
                Remediation = TruncateRequired(outcome.Remediation, 2000),
                Status = outcome.Status,
                ActualValue = TruncateNullable(outcome.ActualValue, 500),
                ExpectedValue = TruncateNullable(outcome.ExpectedValue, 500),
                Message = TruncateNullable(outcome.Message, 1000)
            });
        }

        var finishedAtUtc = utcNow.UtcDateTime;

        computerAudit.Score = evaluation.Score;
        computerAudit.OverallRisk = evaluation.OverallRisk;
        computerAudit.PassedCount = evaluation.Passed;
        computerAudit.FailedCount = evaluation.Failed;
        computerAudit.ErrorCount = evaluation.Errors;
        computerAudit.ErrorMessage = null;
        computerAudit.OsCaption = TruncateNullable(facts.Os?.Caption, 200);
        computerAudit.OsVersion = TruncateNullable(facts.Os?.Version, 100);
        computerAudit.PsVersion = TruncateNullable(facts.Os?.PsVersion, 50);
        computerAudit.FinishedAt = finishedAtUtc;
        computerAudit.Status = ComputerAuditStatus.Completed;

        computer.LastAuditedAt = finishedAtUtc;
        computer.LastScore = evaluation.Score;
        computer.LastRiskLevel = evaluation.OverallRisk;

        return checkResults;
    }

    private static bool IsTerminalComputerStatus(ComputerAuditStatus status) =>
        status is ComputerAuditStatus.Completed or ComputerAuditStatus.Unreachable or ComputerAuditStatus.Failed;

    private static string TruncateRequired(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var trimmed = value.Trim();
        return trimmed.Length <= maxLength ? trimmed : trimmed[..(maxLength - 3)] + "...";
    }

    private static string? TruncateNullable(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var trimmed = value.Trim();
        return trimmed.Length <= maxLength ? trimmed : trimmed[..(maxLength - 3)] + "...";
    }
}

