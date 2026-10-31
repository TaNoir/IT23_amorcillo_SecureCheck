using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

public class AuditQueueAndAlertTests
{
    // ---------- 1. AuditQueue ----------

    [Fact]
    public async Task EnqueueAsync_and_DequeueAsync_preserve_FIFO_order()
    {
        var queue = new AuditQueue();

        await queue.EnqueueAsync(10);
        await queue.EnqueueAsync(25);
        await queue.EnqueueAsync(42);

        Assert.Equal(10, await queue.DequeueAsync());
        Assert.Equal(25, await queue.DequeueAsync());
        Assert.Equal(42, await queue.DequeueAsync());
    }

    [Fact]
    public async Task ReadAllAsync_streams_enqueued_run_ids_until_cancelled()
    {
        var queue = new AuditQueue();
        using var cts = new CancellationTokenSource();

        await queue.EnqueueAsync(1);
        await queue.EnqueueAsync(2);
        await queue.EnqueueAsync(3);

        var received = new List<int>();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var id in queue.ReadAllAsync(cts.Token))
            {
                received.Add(id);
                if (received.Count == 3)
                {
                    cts.Cancel();
                }
            }
        });

        Assert.Equal(new[] { 1, 2, 3 }, received);
    }

    [Fact]
    public async Task Concurrent_producers_enqueue_all_run_ids_without_loss()
    {
        var queue = new AuditQueue();
        const int count = 40;

        var producerTasks = Enumerable.Range(1, count)
            .Select(id => Task.Run(async () => await queue.EnqueueAsync(id)));
        await Task.WhenAll(producerTasks);

        var dequeued = new List<int>(count);
        for (var i = 0; i < count; i++)
        {
            dequeued.Add(await queue.DequeueAsync());
        }

        Assert.Equal(count, dequeued.Distinct().Count());
        Assert.Equal(Enumerable.Range(1, count), dequeued.OrderBy(x => x));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-99)]
    public async Task EnqueueAsync_rejects_zero_or_negative_run_ids(int invalidRunId)
    {
        var queue = new AuditQueue();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            queue.EnqueueAsync(invalidRunId).AsTask());
    }

    // ---------- 2. AlertService ----------

    [Fact]
    public async Task BuildAlertIfNeeded_creates_Critical_alert_with_exact_finding_counts_for_weak_pc_fixture()
    {
        var json = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "weak-pc.json"));
        var checks = GetSeededChecksWithIds();
        var evaluator = new AuditEvaluator();
        var computer = new Computer { Id = 7, Name = "SC-LAB-01", HostName = "demo:weak" };
        var audit = new ComputerAudit { Id = 15, AuditRunId = 3, ComputerId = computer.Id };
        var now = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);

        var checkResults = AuditWorker.ApplySuccessfulRunJson(audit, computer, json, checks, evaluator, now);
        var alert = AlertService.BuildAlertIfNeeded(audit, computer.Name, checkResults, now.UtcDateTime);

        Assert.NotNull(alert);
        Assert.Equal(computer.Id, alert!.ComputerId);
        Assert.Equal(audit.Id, alert.ComputerAuditId);
        Assert.Equal(RiskLevel.Critical, alert.Severity);
        Assert.False(alert.IsAcknowledged);
        Assert.Null(alert.AcknowledgedByName);
        Assert.Null(alert.AcknowledgedAt);
        Assert.Equal("SC-LAB-01: 2 Critical and 2 High findings (score 50)", alert.Message);
    }

    [Fact]
    public void BuildAlertIfNeeded_creates_High_alert_with_singular_and_plural_High_finding_messages()
    {
        var auditSingle = new ComputerAudit
        {
            Id = 20,
            ComputerId = 5,
            Status = ComputerAuditStatus.Completed,
            OverallRisk = RiskLevel.High,
            Score = 89
        };
        var resultsSingle = new[]
        {
            new CheckResult { Code = "FW-PRIVATE", RiskLevel = RiskLevel.High, Status = CheckStatus.Fail },
            new CheckResult { Code = "SVC-TELNET", RiskLevel = RiskLevel.Low, Status = CheckStatus.Fail },
            new CheckResult { Code = "FW-PUBLIC", RiskLevel = RiskLevel.Critical, Status = CheckStatus.Pass }
        };

        var alertSingle = AlertService.BuildAlertIfNeeded(auditSingle, "SC-OFFICE-01", resultsSingle);

        Assert.NotNull(alertSingle);
        Assert.Equal(RiskLevel.High, alertSingle!.Severity);
        Assert.Equal("SC-OFFICE-01: 1 High finding (score 89)", alertSingle.Message);

        var auditPlural = new ComputerAudit
        {
            Id = 21,
            ComputerId = 5,
            Status = ComputerAuditStatus.Completed,
            OverallRisk = RiskLevel.High,
            Score = 76
        };
        var resultsPlural = new[]
        {
            new CheckResult { Code = "FW-DOMAIN", RiskLevel = RiskLevel.High, Status = CheckStatus.Fail },
            new CheckResult { Code = "FW-PRIVATE", RiskLevel = RiskLevel.High, Status = CheckStatus.Fail }
        };

        var alertPlural = AlertService.BuildAlertIfNeeded(auditPlural, "SC-OFFICE-01", resultsPlural);

        Assert.NotNull(alertPlural);
        Assert.Equal(RiskLevel.High, alertPlural!.Severity);
        Assert.Equal("SC-OFFICE-01: 2 High findings (score 76)", alertPlural.Message);
    }

    [Fact]
    public void BuildAlertIfNeeded_creates_Critical_only_alert_message_when_zero_High_failures()
    {
        var audit = new ComputerAudit
        {
            Id = 30,
            ComputerId = 9,
            Status = ComputerAuditStatus.Completed,
            OverallRisk = RiskLevel.Critical,
            Score = 89
        };
        var results = new[]
        {
            new CheckResult { Code = "FW-PUBLIC", RiskLevel = RiskLevel.Critical, Status = CheckStatus.Fail },
            new CheckResult { Code = "FW-DOMAIN", RiskLevel = RiskLevel.High, Status = CheckStatus.Pass }
        };

        var alert = AlertService.BuildAlertIfNeeded(audit, "SC-LAB-03", results);

        Assert.NotNull(alert);
        Assert.Equal(RiskLevel.Critical, alert!.Severity);
        Assert.Equal("SC-LAB-03: 1 Critical finding (score 89)", alert.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(RiskLevel.Low)]
    [InlineData(RiskLevel.Medium)]
    public void BuildAlertIfNeeded_returns_null_for_Low_Medium_and_Secure_overall_risk(RiskLevel? overallRisk)
    {
        var audit = new ComputerAudit
        {
            Id = 40,
            ComputerId = 2,
            Status = ComputerAuditStatus.Completed,
            OverallRisk = overallRisk,
            Score = overallRisk switch
            {
                RiskLevel.Medium => 85,
                RiskLevel.Low => 97,
                _ => 100
            }
        };

        var results = overallRisk.HasValue
            ? new[] { new CheckResult { Code = "TEST", RiskLevel = overallRisk.Value, Status = CheckStatus.Fail } }
            : Array.Empty<CheckResult>();

        var alert = AlertService.BuildAlertIfNeeded(audit, "SC-LAB-02", results);

        Assert.Null(alert);
    }

    [Fact]
    public async Task Secure_pc_fixture_produces_no_alert()
    {
        var json = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "secure-pc.json"));
        var checks = GetSeededChecksWithIds();
        var evaluator = new AuditEvaluator();
        var computer = new Computer { Id = 8, Name = "SC-LAB-02", HostName = "demo:secure" };
        var audit = new ComputerAudit { Id = 41, AuditRunId = 3, ComputerId = computer.Id };

        var checkResults = AuditWorker.ApplySuccessfulRunJson(audit, computer, json, checks, evaluator, DateTimeOffset.UtcNow);
        var alert = AlertService.BuildAlertIfNeeded(audit, computer.Name, checkResults);

        Assert.Equal(ComputerAuditStatus.Completed, audit.Status);
        Assert.Equal(100, audit.Score);
        Assert.Null(audit.OverallRisk);
        Assert.Null(alert);
    }

    [Theory]
    [InlineData(ComputerAuditStatus.Pending)]
    [InlineData(ComputerAuditStatus.Running)]
    [InlineData(ComputerAuditStatus.Unreachable)]
    [InlineData(ComputerAuditStatus.Failed)]
    public void BuildAlertIfNeeded_returns_null_when_ComputerAudit_is_not_Completed(ComputerAuditStatus status)
    {
        var audit = new ComputerAudit
        {
            Id = 50,
            ComputerId = 4,
            Status = status,
            OverallRisk = RiskLevel.Critical,
            Score = 30
        };
        var results = new[]
        {
            new CheckResult { Code = "FW-PUBLIC", RiskLevel = RiskLevel.Critical, Status = CheckStatus.Fail }
        };

        Assert.Null(AlertService.BuildAlertIfNeeded(audit, "SC-LAB-01", results));
    }

    [Fact]
    public void BuildAlertIfNeeded_respects_500_character_Alert_Message_limit()
    {
        var veryLongName = new string('A', 600);
        var audit = new ComputerAudit
        {
            Id = 60,
            ComputerId = 1,
            Status = ComputerAuditStatus.Completed,
            OverallRisk = RiskLevel.Critical,
            Score = 40
        };
        var results = new[]
        {
            new CheckResult { Code = "AV-ENABLED", RiskLevel = RiskLevel.Critical, Status = CheckStatus.Fail }
        };

        var alert = AlertService.BuildAlertIfNeeded(audit, veryLongName, results);

        Assert.NotNull(alert);
        Assert.True(alert!.Message.Length <= 500);
    }

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
