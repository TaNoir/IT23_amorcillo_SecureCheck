using System.Globalization;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;
using DiagnosticsIndexModel = SecureCheck.Web.Pages.Admin.Diagnostics.IndexModel;

namespace SecureCheck.Tests;

public class AuditEvaluatorTests
{
    private static readonly DateTimeOffset FixedNow =
        DateTimeOffset.Parse("2026-10-29T09:00:00+08:00", CultureInfo.InvariantCulture);

    private readonly AuditEvaluator _evaluator = new();

    // ---------- 1. AuditFacts JSON Deserialization & Safe TryParse ----------

    [Theory]
    [InlineData("secure-pc.json", "SC-LAB-02")]
    [InlineData("weak-pc.json", "SC-LAB-01")]
    [InlineData("partial-error.json", "SC-LAB-02")]
    public void TryParse_deserializes_all_three_fixtures_cleanly(string fixtureName, string expectedComputerName)
    {
        var json = ReadFixtureJson(fixtureName);

        var ok = AuditFacts.TryParse(json, out var facts, out var error);

        Assert.True(ok, error);
        Assert.Null(error);
        Assert.NotNull(facts);
        Assert.Equal(1, facts.SchemaVersion);
        Assert.Equal(expectedComputerName, facts.ComputerName);
        Assert.Equal(FixedNow, facts.CollectedAt);
        Assert.NotNull(facts.Os);
        Assert.NotNull(facts.Firewall);
        Assert.NotNull(facts.Updates);
        Assert.NotNull(facts.Antivirus);
        Assert.NotNull(facts.Accounts);
        Assert.NotNull(facts.ServicesAndFeatures);
    }

    [Fact]
    public void TryParse_is_case_insensitive_allows_nulls_and_isolates_unparseable_date_strings()
    {
        const string json = """
        {
          "SCHEMAVERSION": 1,
          "ComputerName": "LAB-CASE-01",
          "FIREWALL": {
            "ERROR": null,
            "PROFILES": [
              { "NAME": "Domain", "ENABLED": true }
            ]
          },
          "Updates": {
            "LastInstalledOn": "not-a-valid-date"
          },
          "Antivirus": null
        }
        """;

        var ok = AuditFacts.TryParse(json, out var facts, out var error);

        Assert.True(ok, error);
        Assert.NotNull(facts);
        Assert.Equal("LAB-CASE-01", facts.ComputerName);
        Assert.Single(facts.Firewall!.Profiles!);
        Assert.True(facts.Firewall.Profiles![0].Enabled);
        Assert.Null(facts.Updates!.LastInstalledOn);
        Assert.Null(facts.Antivirus);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \r\n  ")]
    [InlineData("{ malformed json")]
    [InlineData("[]")]
    [InlineData("42")]
    [InlineData("null")]
    [InlineData("\"just a string\"")]
    [InlineData("{\"schemaVersion\": 99, \"computerName\": \"FUTURE\"}")]
    public void TryParse_returns_false_with_message_and_never_throws_on_invalid_or_unsupported_json(string? badJson)
    {
        var ok = AuditFacts.TryParse(badJson, out var facts, out var error);

        Assert.False(ok);
        Assert.Null(facts);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    // ---------- 2. Fixture End-to-End Evaluation Tests ----------

    [Fact]
    public void Secure_pc_fixture_evaluates_all_16_checks_as_Pass_with_Score_100_and_null_OverallRisk()
    {
        var facts = ParseFixture("secure-pc.json");
        var checks = DbSeeder.GetDefaultChecks();

        var result = _evaluator.Evaluate(facts, checks, FixedNow);

        Assert.Equal(16, result.Outcomes.Count);
        Assert.Equal(16, result.Passed);
        Assert.Equal(0, result.Failed);
        Assert.Equal(0, result.Errors);
        Assert.Equal(0, result.Skipped);
        Assert.Equal(100, result.Score);
        Assert.Null(result.OverallRisk);

        Assert.All(result.Outcomes, outcome =>
        {
            Assert.Equal(CheckStatus.Pass, outcome.Status);
            Assert.False(string.IsNullOrWhiteSpace(outcome.Code));
            Assert.False(string.IsNullOrWhiteSpace(outcome.Name));
            Assert.False(string.IsNullOrWhiteSpace(outcome.Remediation));
            Assert.False(string.IsNullOrWhiteSpace(outcome.ActualValue));
            Assert.False(string.IsNullOrWhiteSpace(outcome.ExpectedValue));
            Assert.False(string.IsNullOrWhiteSpace(outcome.Message));
        });
    }

    [Fact]
    public void Weak_pc_fixture_produces_expected_8_failures_Critical_overall_risk_and_hand_calculated_score()
    {
        // Hand calculation of Score for weak-pc.json using PROJECT_BRIEF weights
        // (Low = 1, Medium = 2, High = 3, Critical = 4):
        //
        // Passed checks (8):
        //   FW-DOMAIN      (High)     = 3
        //   FW-PRIVATE     (High)     = 3
        //   AV-ENABLED     (Critical) = 4
        //   AV-REALTIME    (High)     = 3
        //   AV-SIGNATURES  (Medium)   = 2
        //   ACC-ADMINS     (Medium)   = 2
        //   SVC-REMOTEREG  (Medium)   = 2
        //   SVC-RDP        (Medium)   = 2
        //   -----------------------------
        //   PassWeight                = 21
        //
        // Failed checks (8):
        //   FW-PUBLIC      (Critical) = 4
        //   UPD-RECENT     (High)     = 3   (2026-07-31 -> 90 days ago > 30)
        //   ACC-GUEST      (High)     = 3
        //   ACC-PWLENGTH   (Medium)   = 2   (0 < 8)
        //   ACC-PWCOMPLEX  (Medium)   = 2   (0 != 1)
        //   ACC-LOCKOUT    (Medium)   = 2   (0 disabled, not in 1..10)
        //   SVC-SMB1       (Critical) = 4
        //   SVC-TELNET     (Low)      = 1
        //   -----------------------------
        //   FailWeight                = 21
        //
        // Total evaluated weight = 21 + 21 = 42
        // Score = round(100 * 21 / 42) = 50
        // OverallRisk = highest RiskLevel among Failed checks = RiskLevel.Critical

        var facts = ParseFixture("weak-pc.json");
        var checks = DbSeeder.GetDefaultChecks();

        var result = _evaluator.Evaluate(facts, checks, FixedNow);

        var expectedFailedCodes = new[]
        {
            "FW-PUBLIC",
            "UPD-RECENT",
            "ACC-GUEST",
            "ACC-PWLENGTH",
            "ACC-PWCOMPLEX",
            "ACC-LOCKOUT",
            "SVC-SMB1",
            "SVC-TELNET"
        };

        var actualFailedCodes = result.Outcomes
            .Where(o => o.Status == CheckStatus.Fail)
            .Select(o => o.Code)
            .ToArray();

        Assert.Equal(expectedFailedCodes, actualFailedCodes);
        Assert.Equal(8, result.Passed);
        Assert.Equal(8, result.Failed);
        Assert.Equal(0, result.Errors);
        Assert.Equal(0, result.Skipped);
        Assert.Equal(RiskLevel.Critical, result.OverallRisk);
        Assert.Equal(50, result.Score);
    }

    [Fact]
    public void Partial_error_fixture_marks_AV_checks_as_Error_and_excludes_them_from_score()
    {
        var facts = ParseFixture("partial-error.json");
        var checks = DbSeeder.GetDefaultChecks();

        var result = _evaluator.Evaluate(facts, checks, FixedNow);

        var errorOutcomes = result.Outcomes.Where(o => o.Status == CheckStatus.Error).ToList();
        Assert.Equal(["AV-ENABLED", "AV-REALTIME", "AV-SIGNATURES"], errorOutcomes.Select(o => o.Code).ToArray());
        Assert.All(errorOutcomes, o =>
            Assert.Equal("Windows Defender status not available (another antivirus may be installed)", o.Message));

        Assert.Equal(13, result.Passed);
        Assert.Equal(0, result.Failed);
        Assert.Equal(3, result.Errors);
        Assert.Equal(100, result.Score);
        Assert.Null(result.OverallRisk);

        // Also verify AV weights (4 + 3 + 2 = 9) are excluded from the denominator when another check fails:
        // Remaining evaluated weight = 42 - 9 = 33. If SVC-TELNET (Low = 1) fails:
        // PassWeight = 32, FailWeight = 1 -> round(100 * 32 / 33) = round(96.969...) = 97 (not 32 / 42 = 76).
        facts.ServicesAndFeatures!.TelnetClient!.FeatureState = "Enabled";
        var resultWithTelnetFailure = _evaluator.Evaluate(facts, checks, FixedNow);

        Assert.Equal(12, resultWithTelnetFailure.Passed);
        Assert.Equal(1, resultWithTelnetFailure.Failed);
        Assert.Equal(3, resultWithTelnetFailure.Errors);
        Assert.Equal(97, resultWithTelnetFailure.Score);
        Assert.Equal(RiskLevel.Low, resultWithTelnetFailure.OverallRisk);
    }

    // ---------- 3. Dynamic Threshold & Boundary Tests ----------

    [Fact]
    public void UPD_RECENT_uses_CheckDefinition_Threshold_dynamically_for_45_day_old_update()
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Updates!.LastInstalledOn = FixedNow.AddDays(-45);

        var check90 = CloneSingleCheck("UPD-RECENT", threshold: 90);
        var passResult = _evaluator.Evaluate(facts, [check90], FixedNow);
        var passOutcome = Assert.Single(passResult.Outcomes);
        Assert.Equal(CheckStatus.Pass, passOutcome.Status);
        Assert.Equal("45 days ago", passOutcome.ActualValue);
        Assert.Equal("≤ 90 days", passOutcome.ExpectedValue);
        Assert.Equal(100, passResult.Score);

        var check30 = CloneSingleCheck("UPD-RECENT", threshold: 30);
        var failResult = _evaluator.Evaluate(facts, [check30], FixedNow);
        var failOutcome = Assert.Single(failResult.Outcomes);
        Assert.Equal(CheckStatus.Fail, failOutcome.Status);
        Assert.Equal("45 days ago", failOutcome.ActualValue);
        Assert.Equal("≤ 30 days", failOutcome.ExpectedValue);
        Assert.Equal(0, failResult.Score);
    }

    [Theory]
    [InlineData(0, 30, CheckStatus.Pass)]
    [InlineData(30, 30, CheckStatus.Pass)]
    [InlineData(31, 30, CheckStatus.Fail)]
    public void UPD_RECENT_handles_exact_threshold_boundaries(int daysOld, int threshold, CheckStatus expected)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Updates!.LastInstalledOn = FixedNow.AddDays(-daysOld);
        var check = CloneSingleCheck("UPD-RECENT", threshold);

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expected, outcome.Status);
    }

    [Theory]
    [InlineData(0, 10, CheckStatus.Fail, "Disabled (0)")]
    [InlineData(1, 10, CheckStatus.Pass, "1 attempt")]
    [InlineData(5, 10, CheckStatus.Pass, "5 attempts")]
    [InlineData(10, 10, CheckStatus.Pass, "10 attempts")]
    [InlineData(11, 10, CheckStatus.Fail, "11 attempts")]
    [InlineData(6, 5, CheckStatus.Fail, "6 attempts")]
    [InlineData(5, 5, CheckStatus.Pass, "5 attempts")]
    public void ACC_LOCKOUT_enforces_1_through_dynamic_threshold_range(
        int lockoutBadCount,
        int threshold,
        CheckStatus expectedStatus,
        string expectedActual)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Accounts!.PasswordPolicy!.LockoutBadCount = lockoutBadCount;
        var check = CloneSingleCheck("ACC-LOCKOUT", threshold);

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expectedStatus, outcome.Status);
        Assert.Equal(expectedActual, outcome.ActualValue);
        Assert.Equal($"1–{threshold} attempts", outcome.ExpectedValue);
    }

    [Theory]
    [InlineData(7, 7, CheckStatus.Pass)]
    [InlineData(8, 7, CheckStatus.Fail)]
    [InlineData(12, 14, CheckStatus.Pass)]
    public void AV_SIGNATURES_uses_dynamic_threshold(int ageDays, int threshold, CheckStatus expected)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Antivirus!.SignatureAgeDays = ageDays;
        var check = CloneSingleCheck("AV-SIGNATURES", threshold);

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expected, outcome.Status);
    }

    [Theory]
    [InlineData(2, 2, CheckStatus.Pass, "2 admins", "≤ 2 admins")]
    [InlineData(3, 2, CheckStatus.Fail, "3 admins", "≤ 2 admins")]
    [InlineData(3, 4, CheckStatus.Pass, "3 admins", "≤ 4 admins")]
    [InlineData(1, 1, CheckStatus.Pass, "1 admin", "≤ 1 admin")]
    public void ACC_ADMINS_uses_dynamic_threshold_and_formats_counts(
        int adminCount,
        int threshold,
        CheckStatus expected,
        string expectedActual,
        string expectedTarget)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Accounts!.Administrators!.Count = adminCount;
        var check = CloneSingleCheck("ACC-ADMINS", threshold);

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expected, outcome.Status);
        Assert.Equal(expectedActual, outcome.ActualValue);
        Assert.Equal(expectedTarget, outcome.ExpectedValue);
    }

    [Theory]
    [InlineData(7, 8, CheckStatus.Fail)]
    [InlineData(8, 8, CheckStatus.Pass)]
    [InlineData(12, 14, CheckStatus.Fail)]
    [InlineData(14, 14, CheckStatus.Pass)]
    public void ACC_PWLENGTH_uses_dynamic_threshold(int minLen, int threshold, CheckStatus expected)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Accounts!.PasswordPolicy!.MinimumPasswordLength = minLen;
        var check = CloneSingleCheck("ACC-PWLENGTH", threshold);

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expected, outcome.Status);
    }

    [Theory]
    [InlineData(false, null, CheckStatus.Pass, "Not present")]
    [InlineData(true, false, CheckStatus.Pass, "Disabled")]
    [InlineData(true, true, CheckStatus.Fail, "Enabled")]
    [InlineData(true, null, CheckStatus.Error, null)]
    public void ACC_GUEST_handles_missing_disabled_enabled_and_null_states(
        bool exists,
        bool? enabled,
        CheckStatus expectedStatus,
        string? expectedActual)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Accounts!.Guest = new GuestAccountFacts { Exists = exists, Enabled = enabled };
        var check = CloneSingleCheck("ACC-GUEST");

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expectedStatus, outcome.Status);
        Assert.Equal(expectedActual, outcome.ActualValue);
    }

    [Theory]
    [InlineData(false, null, null, CheckStatus.Pass)]
    [InlineData(true, "Stopped", "Disabled", CheckStatus.Pass)]
    [InlineData(true, "Stopped", "Manual", CheckStatus.Pass)]
    [InlineData(true, "Running", "Manual", CheckStatus.Fail)]
    [InlineData(true, "Stopped", "Automatic", CheckStatus.Fail)]
    [InlineData(true, "Stopped", "AutomaticDelayedStart", CheckStatus.Fail)]
    [InlineData(true, "Running", "Automatic", CheckStatus.Fail)]
    [InlineData(true, null, "Disabled", CheckStatus.Error)]
    public void SVC_REMOTEREG_passes_only_when_not_running_and_not_automatic_or_not_installed(
        bool exists,
        string? status,
        string? startType,
        CheckStatus expected)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.ServicesAndFeatures!.RemoteRegistry = new RemoteRegistryFacts
        {
            Exists = exists,
            Status = status,
            StartType = startType
        };
        var check = CloneSingleCheck("SVC-REMOTEREG");

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expected, outcome.Status);
    }

    [Theory]
    [InlineData(false, "Disabled", CheckStatus.Pass)]
    [InlineData(false, "DisabledWithPayloadRemoved", CheckStatus.Pass)]
    [InlineData(false, "NotPresent", CheckStatus.Pass)]
    [InlineData(true, "Disabled", CheckStatus.Fail)]
    [InlineData(false, "Enabled", CheckStatus.Fail)]
    [InlineData(false, "EnablePending", CheckStatus.Fail)]
    [InlineData(true, "Enabled", CheckStatus.Fail)]
    public void SVC_SMB1_requires_both_server_protocol_disabled_and_feature_not_enabled(
        bool serverProtocolEnabled,
        string featureState,
        CheckStatus expected)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.ServicesAndFeatures!.Smb1 = new Smb1Facts
        {
            ServerProtocolEnabled = serverProtocolEnabled,
            FeatureState = featureState
        };
        var check = CloneSingleCheck("SVC-SMB1");

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expected, outcome.Status);
    }

    [Theory]
    [InlineData(false, CheckStatus.Pass, "Off")]
    [InlineData(true, CheckStatus.Fail, "On")]
    public void SVC_RDP_evaluates_rdpEnabled_flag(bool rdpEnabled, CheckStatus expected, string expectedActual)
    {
        var facts = ParseFixture("secure-pc.json");
        facts.ServicesAndFeatures!.RdpEnabled = rdpEnabled;
        var check = CloneSingleCheck("SVC-RDP");

        var outcome = Assert.Single(_evaluator.Evaluate(facts, [check], FixedNow).Outcomes);

        Assert.Equal(expected, outcome.Status);
        Assert.Equal(expectedActual, outcome.ActualValue);
        Assert.Equal("Off", outcome.ExpectedValue);
    }

    // ---------- 4. Disabled Checks, Unknown Codes, All-Error Score, & OverallRisk ----------

    [Fact]
    public void Disabled_checks_are_not_evaluated_and_do_not_affect_score_or_overall_risk()
    {
        var facts = ParseFixture("weak-pc.json");
        var checks = DbSeeder.GetDefaultChecks().ToList();

        // Disable every check that fails on weak-pc.json; only the 8 passing checks remain enabled.
        foreach (var c in checks.Where(c => c.Code is "FW-PUBLIC" or "UPD-RECENT" or "ACC-GUEST"
                     or "ACC-PWLENGTH" or "ACC-PWCOMPLEX" or "ACC-LOCKOUT" or "SVC-SMB1" or "SVC-TELNET"))
        {
            c.IsEnabled = false;
        }

        var result = _evaluator.Evaluate(facts, checks, FixedNow);

        Assert.Equal(8, result.Outcomes.Count);
        Assert.DoesNotContain(result.Outcomes, o => o.Code == "FW-PUBLIC");
        Assert.Equal(8, result.Passed);
        Assert.Equal(0, result.Failed);
        Assert.Equal(100, result.Score);
        Assert.Null(result.OverallRisk);
    }

    [Fact]
    public void Unknown_check_code_returns_Skipped_and_is_excluded_from_score_and_counts()
    {
        var facts = ParseFixture("secure-pc.json");
        var checks = new List<CheckDefinition>
        {
            CloneSingleCheck("FW-DOMAIN"),
            new()
            {
                Id = 999,
                Code = "CUSTOM-UNKNOWN",
                Name = "Future Custom Check",
                Category = CheckCategory.ServicesAndFeatures,
                RiskLevel = RiskLevel.Critical,
                Remediation = "N/A",
                IsEnabled = true
            }
        };

        var result = _evaluator.Evaluate(facts, checks, FixedNow);

        Assert.Equal(2, result.Outcomes.Count);
        var skipped = Assert.Single(result.Outcomes, o => o.Code == "CUSTOM-UNKNOWN");
        Assert.Equal(CheckStatus.Skipped, skipped.Status);
        Assert.Equal(1, result.Passed);
        Assert.Equal(0, result.Failed);
        Assert.Equal(0, result.Errors);
        Assert.Equal(1, result.Skipped);
        Assert.Equal(100, result.Score);
        Assert.Null(result.OverallRisk);
    }

    [Fact]
    public void Score_and_OverallRisk_are_null_when_every_check_is_Error()
    {
        var emptyFacts = new AuditFacts { SchemaVersion = 1, ComputerName = "BROKEN-PC" };
        var checks = DbSeeder.GetDefaultChecks();

        var result = _evaluator.Evaluate(emptyFacts, checks, FixedNow);

        Assert.Equal(16, result.Outcomes.Count);
        Assert.All(result.Outcomes, o => Assert.Equal(CheckStatus.Error, o.Status));
        Assert.Equal(0, result.Passed);
        Assert.Equal(0, result.Failed);
        Assert.Equal(16, result.Errors);
        Assert.Null(result.Score);
        Assert.Null(result.OverallRisk);
    }

    [Fact]
    public void Sub_section_errors_isolate_to_only_affected_checks()
    {
        var facts = ParseFixture("secure-pc.json");
        facts.Accounts!.PasswordPolicy!.Error = "secedit and net accounts failed";
        facts.ServicesAndFeatures!.Smb1!.Error = "LanmanServer registry unreadable";

        var result = _evaluator.Evaluate(facts, DbSeeder.GetDefaultChecks(), FixedNow);

        var errorCodes = result.Outcomes
            .Where(o => o.Status == CheckStatus.Error)
            .Select(o => o.Code)
            .ToArray();

        Assert.Equal(["ACC-PWLENGTH", "ACC-PWCOMPLEX", "ACC-LOCKOUT", "SVC-SMB1"], errorCodes);
        Assert.Equal(12, result.Passed);
        Assert.Equal(4, result.Errors);
        Assert.Equal(100, result.Score);
    }

    [Theory]
    [InlineData(null, "Not Evaluated", "status-error")]
    [InlineData(95, "Good", "risk-low")]
    [InlineData(90, "Good", "risk-low")]
    [InlineData(89, "Fair", "risk-medium")]
    [InlineData(70, "Fair", "risk-medium")]
    [InlineData(69, "Poor", "risk-high")]
    [InlineData(50, "Poor", "risk-high")]
    [InlineData(49, "Critical", "risk-critical")]
    public void DescribeScore_maps_thresholds_from_AppSettings_correctly(
        int? score,
        string expectedLabel,
        string expectedBadge)
    {
        var (label, badgeClass, _) = AuditEvaluator.DescribeScore(score, goodMin: 90, fairMin: 70, poorMin: 50);

        Assert.Equal(expectedLabel, label);
        Assert.Equal(expectedBadge, badgeClass);
    }

    // ---------- 5. Diagnostics Evaluation Integration & Live Local Evaluation ----------

    [Fact]
    public void Diagnostics_enabled_checklist_SQL_filters_IsEnabled_and_orders_by_SortOrder()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlServer("Server=.;Database=SecureCheckModelInspection;Trusted_Connection=True")
            .Options;
        using var db = new ApplicationDbContext(options);

        var sql = DiagnosticsIndexModel.ApplyEnabledChecklistOrder(db.CheckDefinitions).ToQueryString();

        Assert.Contains("[c].[IsEnabled]", sql);
        Assert.Contains("ORDER BY [c].[SortOrder]", sql);
    }

    [Fact]
    public void Diagnostics_TryEvaluatePayload_evaluates_raw_json_preview_and_applies_AppSettings_score_labels()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlServer("Server=.;Database=SecureCheckModelInspection;Trusted_Connection=True")
            .Options;
        using var db = new ApplicationDbContext(options);
        var runner = new PowerShellRunner();
        var evaluator = new AuditEvaluator();
        var activityLog = new ActivityLogService(db);

        var pageModel = new DiagnosticsIndexModel(db, runner, evaluator, activityLog);
        var checks = DbSeeder.GetDefaultChecks();
        var settings = DbSeeder.GetDefaultSettings().ToDictionary(s => s.Key, s => s.Value);
        var weakJson = ReadFixtureJson("weak-pc.json");

        var ok = pageModel.TryEvaluatePayload(weakJson, checks, settings, FixedNow);

        Assert.True(ok);
        Assert.Null(pageModel.ErrorMessage);
        Assert.NotNull(pageModel.ParsedFacts);
        Assert.NotNull(pageModel.Evaluation);
        Assert.Equal(50, pageModel.Evaluation.Score);
        Assert.Equal(RiskLevel.Critical, pageModel.Evaluation.OverallRisk);
        Assert.Equal("Poor", pageModel.ScoreLabel);
        Assert.Equal("risk-high", pageModel.ScoreBadgeClass);
        Assert.Contains("\"schemaVersion\": 1", pageModel.PrettyJson);
    }

    [Fact]
    public async Task Live_localhost_audit_json_parses_and_evaluates_all_16_checks_cleanly()
    {
        var runner = new PowerShellRunner();
        var runResult = await runner.RunAuditAsync("localhost", userName: null, password: null, timeoutSeconds: 30);

        Assert.True(runResult.Success, runResult.ErrorMessage);
        Assert.True(AuditFacts.TryParse(runResult.Json, out var facts, out var parseError), parseError);

        var evalResult = _evaluator.Evaluate(facts, DbSeeder.GetDefaultChecks(), DateTimeOffset.UtcNow);

        Assert.Equal(16, evalResult.Outcomes.Count);
        Assert.Equal(16, evalResult.Passed + evalResult.Failed + evalResult.Errors + evalResult.Skipped);
        Assert.DoesNotContain(evalResult.Outcomes, o => o.Status == CheckStatus.Skipped);
        Assert.NotNull(evalResult.Score);
        Assert.InRange(evalResult.Score.Value, 0, 100);
    }

    // ---------- Helpers ----------

    private static string ReadFixtureJson(string fileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);
        return File.ReadAllText(path);
    }

    private static AuditFacts ParseFixture(string fileName)
    {
        var json = ReadFixtureJson(fileName);
        Assert.True(AuditFacts.TryParse(json, out var facts, out var error), error);
        return facts;
    }

    private static CheckDefinition CloneSingleCheck(string code, int? threshold = null)
    {
        var seed = Assert.Single(DbSeeder.GetDefaultChecks(), c => c.Code == code);
        return new CheckDefinition
        {
            Id = seed.Id,
            Code = seed.Code,
            Name = seed.Name,
            Category = seed.Category,
            Description = seed.Description,
            RiskLevel = seed.RiskLevel,
            Threshold = threshold ?? seed.Threshold,
            ThresholdLabel = seed.ThresholdLabel,
            Remediation = seed.Remediation,
            IsEnabled = true,
            SortOrder = seed.SortOrder
        };
    }
}
