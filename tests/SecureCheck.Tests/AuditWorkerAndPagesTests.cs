using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Pages.Audits;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

public class AuditWorkerAndPagesTests
{
    // ---------- 1. AuditWorker Error & Status Mapping ----------

    [Theory]
    [InlineData(RunnerErrorKind.Unreachable, ComputerAuditStatus.Unreachable)]
    [InlineData(RunnerErrorKind.AccessDenied, ComputerAuditStatus.Unreachable)]
    [InlineData(RunnerErrorKind.NotTrusted, ComputerAuditStatus.Unreachable)]
    [InlineData(RunnerErrorKind.Timeout, ComputerAuditStatus.Unreachable)]
    [InlineData(RunnerErrorKind.Other, ComputerAuditStatus.Failed)]
    [InlineData(null, ComputerAuditStatus.Failed)]
    public void MapFailureStatus_maps_reachability_auth_trust_and_timeout_to_Unreachable_and_Other_to_Failed(
        RunnerErrorKind? errorKind,
        ComputerAuditStatus expectedStatus)
    {
        Assert.Equal(expectedStatus, AuditWorker.MapFailureStatus(errorKind));
    }

    [Fact]
    public void ApplyRunnerFailure_populates_mapped_status_sanitized_message_and_FinishedAt()
    {
        var audit = new ComputerAudit { Id = 1, Status = ComputerAuditStatus.Running };
        var finishedAt = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);

        AuditWorker.ApplyRunnerFailure(
            audit,
            RunnerErrorKind.Unreachable,
            PowerShellRunner.UnreachableFriendlyMessage,
            finishedAt);

        Assert.Equal(ComputerAuditStatus.Unreachable, audit.Status);
        Assert.Equal(PowerShellRunner.UnreachableFriendlyMessage, audit.ErrorMessage);
        Assert.Equal(finishedAt, audit.FinishedAt);
    }

    [Fact]
    public void DetermineFinalRunStatus_returns_Completed_only_when_every_computer_Completed()
    {
        Assert.Equal(
            AuditRunStatus.Completed,
            AuditWorker.DetermineFinalRunStatus(new[]
            {
                ComputerAuditStatus.Completed,
                ComputerAuditStatus.Completed
            }));

        Assert.Equal(
            AuditRunStatus.CompletedWithErrors,
            AuditWorker.DetermineFinalRunStatus(new[]
            {
                ComputerAuditStatus.Completed,
                ComputerAuditStatus.Unreachable
            }));

        Assert.Equal(
            AuditRunStatus.CompletedWithErrors,
            AuditWorker.DetermineFinalRunStatus(new[]
            {
                ComputerAuditStatus.Completed,
                ComputerAuditStatus.Failed
            }));
    }

    // ---------- 2. AuditWorker JSON Evaluation, Snapshots & Clock Selection ----------

    [Fact]
    public void ApplySuccessfulRunJson_marks_Failed_on_invalid_JSON_without_overwriting_Computer_LastAudit_fields()
    {
        var previousAuditDate = new DateTime(2026, 10, 15, 8, 30, 0, DateTimeKind.Utc);
        var computer = new Computer
        {
            Id = 3,
            Name = "SC-LAB-01",
            HostName = "192.168.56.101",
            LastAuditedAt = previousAuditDate,
            LastScore = 92,
            LastRiskLevel = RiskLevel.Low
        };
        var audit = new ComputerAudit { Id = 12, ComputerId = computer.Id, Status = ComputerAuditStatus.Running };
        var now = new DateTimeOffset(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);

        var checkResults = AuditWorker.ApplySuccessfulRunJson(
            audit,
            computer,
            "{ malformed json !!!",
            GetSeededChecksWithIds(),
            new AuditEvaluator(),
            now);

        Assert.Empty(checkResults);
        Assert.Equal(ComputerAuditStatus.Failed, audit.Status);
        Assert.NotNull(audit.ErrorMessage);
        Assert.Contains("Invalid audit JSON", audit.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(now.UtcDateTime, audit.FinishedAt);

        // Previous good audit summary on Computer must not be overwritten by a failed parse.
        Assert.Equal(previousAuditDate, computer.LastAuditedAt);
        Assert.Equal(92, computer.LastScore);
        Assert.Equal(RiskLevel.Low, computer.LastRiskLevel);
    }

    [Fact]
    public async Task ApplySuccessfulRunJson_saves_full_CheckResult_snapshots_OS_metadata_and_Computer_last_audit_fields()
    {
        var json = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "partial-error.json"));
        var checks = GetSeededChecksWithIds();
        var evaluator = new AuditEvaluator();
        var computer = new Computer { Id = 11, Name = "SC-LAB-ERR", HostName = "demo:error" };
        var audit = new ComputerAudit { Id = 99, AuditRunId = 4, ComputerId = computer.Id };
        var now = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var results = AuditWorker.ApplySuccessfulRunJson(audit, computer, json, checks, evaluator, now);

        Assert.Equal(ComputerAuditStatus.Completed, audit.Status);
        Assert.Equal(16, results.Count);
        Assert.Equal(audit.PassedCount + audit.FailedCount + audit.ErrorCount, results.Count);
        Assert.True(audit.ErrorCount >= 3); // Antivirus checks are Error in partial-error.json
        Assert.False(string.IsNullOrWhiteSpace(audit.OsCaption));
        Assert.False(string.IsNullOrWhiteSpace(audit.OsVersion));
        Assert.False(string.IsNullOrWhiteSpace(audit.PsVersion));
        Assert.Equal(json, audit.RawJson);
        Assert.Equal(now.UtcDateTime, audit.FinishedAt);

        // Computer summary columns updated.
        Assert.Equal(now.UtcDateTime, computer.LastAuditedAt);
        Assert.Equal(audit.Score, computer.LastScore);
        Assert.Equal(audit.OverallRisk, computer.LastRiskLevel);

        // Verify snapshot isolation: mutating CheckDefinition afterwards does not alter saved CheckResult copies.
        var fwPublicDef = checks.Single(c => c.Code == "FW-PUBLIC");
        var originalRemediation = fwPublicDef.Remediation;
        fwPublicDef.Name = "Mutated Name";
        fwPublicDef.RiskLevel = RiskLevel.Low;
        fwPublicDef.Remediation = "Mutated Remediation";

        var savedFwPublic = results.Single(r => r.Code == "FW-PUBLIC");
        Assert.Equal(fwPublicDef.Id, savedFwPublic.CheckDefinitionId);
        Assert.NotEqual("Mutated Name", savedFwPublic.Name);
        Assert.Equal(RiskLevel.Critical, savedFwPublic.RiskLevel);
        Assert.Equal(originalRemediation, savedFwPublic.Remediation);
    }

    [Fact]
    public void SelectEvaluationClock_uses_CollectedAt_for_Demo_mode_and_UtcNow_for_Local_and_Remote()
    {
        var collectedAt = new DateTimeOffset(2026, 3, 15, 8, 0, 0, TimeSpan.Zero);
        var serverNow = new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        var facts = new AuditFacts { CollectedAt = collectedAt };

        Assert.Equal(collectedAt, AuditWorker.SelectEvaluationClock("demo:secure", facts, serverNow));
        Assert.Equal(collectedAt, AuditWorker.SelectEvaluationClock("DEMO:WEAK", facts, serverNow));
        Assert.Equal(serverNow, AuditWorker.SelectEvaluationClock("localhost", facts, serverNow));
        Assert.Equal(serverNow, AuditWorker.SelectEvaluationClock("192.168.56.101", facts, serverNow));
    }

    [Theory]
    [InlineData(null, 5)]
    [InlineData("", 5)]
    [InlineData("0", 5)]
    [InlineData("-3", 5)]
    [InlineData("invalid", 5)]
    [InlineData("3", 3)]
    [InlineData("10", 10)]
    [InlineData("999", 50)]
    public void ResolveMaxParallelAudits_defaults_to_5_and_clamps_valid_settings(string? rawValue, int expected)
    {
        var settings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (rawValue is not null)
        {
            settings[AppSettingKeys.MaxParallelAudits] = rawValue;
        }

        Assert.Equal(expected, AuditWorker.ResolveMaxParallelAudits(settings));
    }

    // ---------- 3. Startup Crash Recovery ----------

    [Fact]
    public void ApplyCrashRecovery_recovers_Queued_and_Running_runs_without_touching_finished_runs_or_completed_computers()
    {
        var recoveryTime = new DateTime(2026, 11, 1, 9, 0, 0, DateTimeKind.Utc);
        var earlierFinish = new DateTime(2026, 11, 1, 8, 55, 0, DateTimeKind.Utc);

        var queuedRun = new AuditRun
        {
            Id = 1,
            Status = AuditRunStatus.Queued,
            TotalComputers = 2,
            CompletedComputers = 0,
            ComputerAudits =
            {
                new ComputerAudit { Id = 101, Status = ComputerAuditStatus.Pending },
                new ComputerAudit { Id = 102, Status = ComputerAuditStatus.Pending }
            }
        };

        var partiallyCompletedRunningRun = new AuditRun
        {
            Id = 2,
            Status = AuditRunStatus.Running,
            TotalComputers = 3,
            CompletedComputers = 1,
            ComputerAudits =
            {
                new ComputerAudit
                {
                    Id = 201,
                    Status = ComputerAuditStatus.Completed,
                    Score = 100,
                    FinishedAt = earlierFinish
                },
                new ComputerAudit
                {
                    Id = 202,
                    Status = ComputerAuditStatus.Running
                },
                new ComputerAudit
                {
                    Id = 203,
                    Status = ComputerAuditStatus.Pending
                }
            }
        };

        var alreadyCompletedRun = new AuditRun
        {
            Id = 3,
            Status = AuditRunStatus.Completed,
            TotalComputers = 1,
            CompletedComputers = 1,
            FinishedAt = earlierFinish,
            ComputerAudits =
            {
                new ComputerAudit { Id = 301, Status = ComputerAuditStatus.Completed, FinishedAt = earlierFinish }
            }
        };

        var recoveredCount = AuditWorker.ApplyCrashRecovery(
            new[] { queuedRun, partiallyCompletedRunningRun, alreadyCompletedRun },
            recoveryTime);

        Assert.Equal(2, recoveredCount);

        // Run #1 (was Queued) -> CompletedWithErrors, both Pending ComputerAudits -> Failed ("Interrupted — app restarted").
        Assert.Equal(AuditRunStatus.CompletedWithErrors, queuedRun.Status);
        Assert.Equal(recoveryTime, queuedRun.FinishedAt);
        Assert.Equal(2, queuedRun.CompletedComputers);
        Assert.All(queuedRun.ComputerAudits, ca =>
        {
            Assert.Equal(ComputerAuditStatus.Failed, ca.Status);
            Assert.Equal(AuditWorker.InterruptedErrorMessage, ca.ErrorMessage);
            Assert.Equal(recoveryTime, ca.FinishedAt);
        });

        // Run #2 (was Running) -> CompletedWithErrors; Completed child preserved, Running & Pending -> Failed.
        Assert.Equal(AuditRunStatus.CompletedWithErrors, partiallyCompletedRunningRun.Status);
        Assert.Equal(recoveryTime, partiallyCompletedRunningRun.FinishedAt);
        Assert.Equal(3, partiallyCompletedRunningRun.CompletedComputers);

        var preservedChild = partiallyCompletedRunningRun.ComputerAudits.Single(c => c.Id == 201);
        Assert.Equal(ComputerAuditStatus.Completed, preservedChild.Status);
        Assert.Equal(100, preservedChild.Score);
        Assert.Null(preservedChild.ErrorMessage);
        Assert.Equal(earlierFinish, preservedChild.FinishedAt);

        foreach (var interruptedId in new[] { 202, 203 })
        {
            var interruptedChild = partiallyCompletedRunningRun.ComputerAudits.Single(c => c.Id == interruptedId);
            Assert.Equal(ComputerAuditStatus.Failed, interruptedChild.Status);
            Assert.Equal(AuditWorker.InterruptedErrorMessage, interruptedChild.ErrorMessage);
            Assert.Equal(recoveryTime, interruptedChild.FinishedAt);
        }

        // Run #3 (was already Completed) -> completely untouched.
        Assert.Equal(AuditRunStatus.Completed, alreadyCompletedRun.Status);
        Assert.Equal(earlierFinish, alreadyCompletedRun.FinishedAt);
    }

    // ---------- 4. Concurrent Duplicate Computer Guard ----------

    [Theory]
    [InlineData(ComputerAuditStatus.Pending, true)]
    [InlineData(ComputerAuditStatus.Running, true)]
    [InlineData(ComputerAuditStatus.Completed, false)]
    [InlineData(ComputerAuditStatus.Unreachable, false)]
    [InlineData(ComputerAuditStatus.Failed, false)]
    public void IsBusyStatus_returns_true_only_for_Pending_and_Running(ComputerAuditStatus status, bool expectedBusy)
    {
        Assert.Equal(expectedBusy, RunModel.IsBusyStatus(status));
    }

    [Fact]
    public void GetBusyComputerIdsQuery_generates_SQL_filtering_Pending_and_Running_ComputerAudits()
    {
        using var db = CreateModelInspectionContext();

        var sql = RunModel.GetBusyComputerIdsQuery(db.ComputerAudits, new[] { 1, 2, 3 }).ToQueryString();

        Assert.Contains("Pending", sql, StringComparison.Ordinal);
        Assert.Contains("Running", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("Completed", sql, StringComparison.Ordinal);
    }

    [Fact]
    public void PartitionSelectedComputers_skips_computers_with_active_audits_and_keeps_idle_computers()
    {
        var c1 = new Computer { Id = 1, Name = "SC-LAB-01", HostName = "demo:weak" };
        var c2 = new Computer { Id = 2, Name = "SC-LAB-02", HostName = "demo:secure" };
        var c3 = new Computer { Id = 3, Name = "SC-OFFICE-01", HostName = "localhost" };

        var busyIds = new HashSet<int> { 2 };

        var (eligible, skipped) = RunModel.PartitionSelectedComputers(new[] { c1, c2, c3 }, busyIds);

        Assert.Equal(new[] { 1, 3 }, eligible.Select(c => c.Id));
        Assert.Single(skipped);
        Assert.Equal("SC-LAB-02", skipped[0].Name);
    }

    [Fact]
    public void PartitionSelectedComputers_returns_no_eligible_computers_when_all_selected_are_busy()
    {
        var c1 = new Computer { Id = 1, Name = "SC-LAB-01", HostName = "demo:weak" };
        var c2 = new Computer { Id = 2, Name = "SC-LAB-02", HostName = "demo:secure" };

        var busyIds = new HashSet<int> { 1, 2 };

        var (eligible, skipped) = RunModel.PartitionSelectedComputers(new[] { c1, c2 }, busyIds);

        Assert.Empty(eligible);
        Assert.Equal(2, skipped.Count);
    }

    [Fact]
    public void FormatActivityLogAction_formats_audit_run_start_message()
    {
        Assert.Equal("Started audit run #4 on 3 computers", RunModel.FormatActivityLogAction(4, 3));
    }

    // ---------- 5. Progress Snapshot Mapping ----------

    [Fact]
    public void ProgressModel_MapSnapshot_calculates_progress_percentage_and_reveal_state()
    {
        var run = new AuditRun
        {
            Id = 8,
            StartedByName = "IT Auditor",
            Status = AuditRunStatus.Running,
            TotalComputers = 4,
            CompletedComputers = 2,
            ComputerAudits =
            {
                new ComputerAudit
                {
                    Id = 1,
                    ComputerId = 10,
                    Computer = new Computer { Id = 10, Name = "PC-A", HostName = "demo:secure" },
                    Status = ComputerAuditStatus.Completed,
                    Score = 100,
                    OverallRisk = null,
                    PassedCount = 16
                },
                new ComputerAudit
                {
                    Id = 2,
                    ComputerId = 11,
                    Computer = new Computer { Id = 11, Name = "PC-B", HostName = "192.168.99.99" },
                    Status = ComputerAuditStatus.Unreachable,
                    ErrorMessage = PowerShellRunner.UnreachableFriendlyMessage
                },
                new ComputerAudit
                {
                    Id = 3,
                    ComputerId = 12,
                    Computer = new Computer { Id = 12, Name = "PC-C", HostName = "localhost" },
                    Status = ComputerAuditStatus.Running
                },
                new ComputerAudit
                {
                    Id = 4,
                    ComputerId = 13,
                    Computer = new Computer { Id = 13, Name = "PC-D", HostName = "demo:weak" },
                    Status = ComputerAuditStatus.Pending
                }
            }
        };

        var inProgressSnap = ProgressModel.MapSnapshot(run);
        Assert.False(inProgressSnap.IsFinished);
        Assert.Equal(50, inProgressSnap.PercentComplete);
        Assert.Equal("Secure", inProgressSnap.Computers.Single(c => c.ComputerName == "PC-A").OverallRiskDisplay);
        Assert.True(inProgressSnap.Computers.Single(c => c.ComputerName == "PC-C").IsRunning);

        run.Status = AuditRunStatus.CompletedWithErrors;
        run.CompletedComputers = 4;
        run.FinishedAt = DateTime.UtcNow;

        var finishedSnap = ProgressModel.MapSnapshot(run);
        Assert.True(finishedSnap.IsFinished);
        Assert.Equal(100, finishedSnap.PercentComplete);
        Assert.Equal("Completed with Errors", finishedSnap.StatusDisplay);
    }

    // ---------- 6. Authorization on /Audits/Run and /Audits/Progress ----------

    [Fact]
    public async Task RunModel_enforces_AuditPolicy_allowing_Admin_and_Auditor_and_denying_Viewer_and_Anonymous()
    {
        var authorizeAttr = typeof(RunModel).GetCustomAttribute<AuthorizeAttribute>(inherit: true);
        Assert.NotNull(authorizeAttr);
        Assert.Equal(AppPolicies.Audit, authorizeAttr!.Policy);

        var authService = CreateAuthorizationService();

        Assert.True((await authService.AuthorizeAsync(UserInRole(AppRoles.Administrator), authorizeAttr.Policy!)).Succeeded);
        Assert.True((await authService.AuthorizeAsync(UserInRole(AppRoles.Auditor), authorizeAttr.Policy!)).Succeeded);
        Assert.False((await authService.AuthorizeAsync(UserInRole(AppRoles.Viewer), authorizeAttr.Policy!)).Succeeded);
        Assert.False((await authService.AuthorizeAsync(AnonymousUser(), authorizeAttr.Policy!)).Succeeded);
    }

    [Fact]
    public async Task ProgressModel_uses_FallbackPolicy_so_Viewer_can_view_progress_but_Anonymous_is_denied()
    {
        // ProgressModel intentionally carries no role-restrictive [Authorize(Policy = ...)] attribute,
        // so all authenticated users (including Viewer) pass FallbackPolicy while anonymous requests fail.
        var authorizeAttr = typeof(ProgressModel).GetCustomAttribute<AuthorizeAttribute>(inherit: true);
        Assert.Null(authorizeAttr?.Policy);
        Assert.Null(authorizeAttr?.Roles);

        var options = new AuthorizationOptions();
        SecurityConfig.ConfigureAuthorization(options);
        Assert.NotNull(options.FallbackPolicy);

        var authService = CreateAuthorizationService();

        Assert.True((await authService.AuthorizeAsync(UserInRole(AppRoles.Administrator), options.FallbackPolicy!)).Succeeded);
        Assert.True((await authService.AuthorizeAsync(UserInRole(AppRoles.Auditor), options.FallbackPolicy!)).Succeeded);
        Assert.True((await authService.AuthorizeAsync(UserInRole(AppRoles.Viewer), options.FallbackPolicy!)).Succeeded);
        Assert.False((await authService.AuthorizeAsync(AnonymousUser(), options.FallbackPolicy!)).Succeeded);
    }

    [Fact]
    public void DI_registrations_resolve_AuditQueue_singleton_AlertService_scoped_and_AuditWorker_hosted_service()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddDbContext<ApplicationDbContext>(opt =>
            opt.UseSqlServer("Server=.;Database=SecureCheckDiInspection;Trusted_Connection=True"));
        services.AddSingleton<CredentialProtector>();
        services.AddSingleton<PowerShellRunner>();
        services.AddSingleton<AuditEvaluator>();
        services.AddSingleton<AuditQueue>();
        services.AddScoped<AlertService>();
        services.AddHostedService<AuditWorker>();

        using var provider = services.BuildServiceProvider();

        var q1 = provider.GetRequiredService<AuditQueue>();
        var q2 = provider.GetRequiredService<AuditQueue>();
        Assert.Same(q1, q2);

        using var scope = provider.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<AlertService>());

        var hostedServices = provider.GetServices<IHostedService>();
        Assert.Contains(hostedServices, s => s is AuditWorker);
    }

    // ---------- Helpers ----------

    private static ApplicationDbContext CreateModelInspectionContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlServer("Server=.;Database=SecureCheckModelInspection;Trusted_Connection=True")
            .Options;
        return new ApplicationDbContext(options);
    }

    private static IAuthorizationService CreateAuthorizationService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(SecurityConfig.ConfigureAuthorization);
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    private static ClaimsPrincipal UserInRole(string role) =>
        new(new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.Name, $"{role.ToLowerInvariant()}@securecheck.local"),
                new Claim(ClaimTypes.Role, role)
            },
            authenticationType: "Test"));

    private static ClaimsPrincipal AnonymousUser() => new(new ClaimsIdentity());

    private static List<CheckDefinition> GetSeededChecksWithIds()
    {
        var checks = DbSeeder.GetDefaultChecks().ToList();
        for (var i = 0; i < checks.Count; i++)
        {
            checks[i].Id = i + 1;
        }
        return checks;
    }
}
