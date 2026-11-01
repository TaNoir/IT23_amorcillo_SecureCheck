using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;
using AlertsIndexModel = SecureCheck.Web.Pages.Alerts.IndexModel;
using AuditsDetailsModel = SecureCheck.Web.Pages.Audits.DetailsModel;
using AuditsIndexModel = SecureCheck.Web.Pages.Audits.IndexModel;
using AuditsResultModel = SecureCheck.Web.Pages.Audits.ResultModel;
using ComputerHistoryModel = SecureCheck.Web.Pages.Computers.HistoryModel;
using DashboardIndexModel = SecureCheck.Web.Pages.IndexModel;

namespace SecureCheck.Tests;

public class Phase7DashboardAndResultsTests
{
    // ---------- 1. Safe Remediation Backtick-to-<code> Formatting ----------

    [Fact]
    public void RemediationFormatter_wraps_backticked_commands_in_code_tags_and_preserves_plain_text()
    {
        const string input =
            "Turn on the Public network firewall in Windows Security. Or run: `Set-NetFirewallProfile -Profile Public -Enabled True`";

        var html = RemediationFormatter.FormatToHtml(input);

        Assert.Equal(
            "Turn on the Public network firewall in Windows Security. Or run: <code class=\"sc-fix-cmd\">Set-NetFirewallProfile -Profile Public -Enabled True</code>",
            html);
    }

    [Fact]
    public void RemediationFormatter_supports_multiple_code_spans_and_encodes_angle_bracket_placeholders_like_ACC_ADMINS()
    {
        const string input =
            "Open `lusrmgr.msc` > Groups > Administrators. Or run: `Remove-LocalGroupMember -Group Administrators -Member <name>`";

        var html = RemediationFormatter.FormatToHtml(input);

        Assert.Contains("<code class=\"sc-fix-cmd\">lusrmgr.msc</code>", html, StringComparison.Ordinal);
        Assert.Contains("&gt; Groups &gt; Administrators.", html, StringComparison.Ordinal);
        Assert.Contains(
            "<code class=\"sc-fix-cmd\">Remove-LocalGroupMember -Group Administrators -Member &lt;name&gt;</code>",
            html,
            StringComparison.Ordinal);
        Assert.DoesNotContain("<name>", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RemediationFormatter_html_escapes_script_tags_and_quotes_both_outside_and_inside_backticks()
    {
        const string malicious =
            "Click <script>alert(\"xss\")</script> 'now' & run `<img src=x onerror=\"alert('pwn')\">`";

        var html = RemediationFormatter.FormatToHtml(malicious);

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("</script>", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("&quot;xss&quot;", html, StringComparison.Ordinal);
        Assert.Contains("&#x27;now&#x27;", html, StringComparison.Ordinal);
        Assert.Contains("&amp; run", html, StringComparison.Ordinal);
        Assert.Contains("<code class=\"sc-fix-cmd\">&lt;img src=x onerror=&quot;alert(&#x27;pwn&#x27;)&quot;&gt;</code>", html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("Plain guidance without commands", "Plain guidance without commands")]
    [InlineData("Unmatched ` backtick <tag>", "Unmatched ` backtick &lt;tag&gt;")]
    [InlineData("Empty `` pair and `cmd`", "Empty `` pair and <code class=\"sc-fix-cmd\">cmd</code>")]
    public void RemediationFormatter_handles_null_empty_unmatched_and_empty_backtick_pairs_safely(
        string? input,
        string expectedHtml)
    {
        Assert.Equal(expectedHtml, RemediationFormatter.FormatToHtml(input));
    }

    [Fact]
    public void RemediationFormatter_formats_all_16_seeded_checklist_remediations_without_raw_unescaped_html()
    {
        foreach (var check in DbSeeder.GetDefaultChecks())
        {
            var html = RemediationFormatter.FormatToHtml(check.Remediation);
            Assert.False(string.IsNullOrWhiteSpace(html));

            // Strip legitimate <code class="sc-fix-cmd"> and </code> tags; no other raw '<' or '>' may remain.
            var stripped = html
                .Replace("<code class=\"sc-fix-cmd\">", string.Empty, StringComparison.Ordinal)
                .Replace("</code>", string.Empty, StringComparison.Ordinal);

            Assert.DoesNotContain("<", stripped, StringComparison.Ordinal);
            Assert.DoesNotContain(">", stripped, StringComparison.Ordinal);
        }
    }

    // ---------- 2. Previous-Audit Comparison & Score Delta ----------

    [Fact]
    public void CompareAudits_classifies_NewlyFailing_FixedSinceLastAudit_StillFailing_and_positive_score_delta()
    {
        var previous = new ComputerAudit
        {
            Id = 10,
            ComputerId = 1,
            Status = ComputerAuditStatus.Completed,
            FinishedAt = new DateTime(2026, 11, 1, 8, 0, 0, DateTimeKind.Utc),
            Score = 62,
            CheckResults =
            {
                // Fail -> Pass => Fixed since last audit
                new CheckResult { Code = "FW-PUBLIC", Name = "Public firewall", Category = CheckCategory.Firewall, RiskLevel = RiskLevel.Critical, Status = CheckStatus.Fail },
                // Fail -> Fail => Still failing
                new CheckResult { Code = "ACC-GUEST", Name = "Guest disabled", Category = CheckCategory.Accounts, RiskLevel = RiskLevel.High, Status = CheckStatus.Fail },
                // Pass -> Fail => Newly failing
                new CheckResult { Code = "SVC-RDP", Name = "RDP off", Category = CheckCategory.ServicesAndFeatures, RiskLevel = RiskLevel.Medium, Status = CheckStatus.Pass },
                // Error -> Fail => Newly failing
                new CheckResult { Code = "AV-SIGNATURES", Name = "AV definitions", Category = CheckCategory.Antivirus, RiskLevel = RiskLevel.Medium, Status = CheckStatus.Error },
                // Fail -> Error => NOT Fixed (fact collection failed, not verified as passing)
                new CheckResult { Code = "UPD-RECENT", Name = "Recent update", Category = CheckCategory.Updates, RiskLevel = RiskLevel.High, Status = CheckStatus.Fail },
                // Pass -> Pass => Unchanged passing (in none of the 3 lists)
                new CheckResult { Code = "FW-DOMAIN", Name = "Domain firewall", Category = CheckCategory.Firewall, RiskLevel = RiskLevel.High, Status = CheckStatus.Pass }
            }
        };

        var current = new ComputerAudit
        {
            Id = 15,
            ComputerId = 1,
            Status = ComputerAuditStatus.Completed,
            FinishedAt = new DateTime(2026, 11, 1, 10, 0, 0, DateTimeKind.Utc),
            Score = 80,
            CheckResults =
            {
                new CheckResult { Code = "fw-public", Name = "Public firewall", Category = CheckCategory.Firewall, RiskLevel = RiskLevel.Critical, Status = CheckStatus.Pass },
                new CheckResult { Code = "ACC-GUEST", Name = "Guest disabled", Category = CheckCategory.Accounts, RiskLevel = RiskLevel.High, Status = CheckStatus.Fail },
                new CheckResult { Code = "SVC-RDP", Name = "RDP off", Category = CheckCategory.ServicesAndFeatures, RiskLevel = RiskLevel.Medium, Status = CheckStatus.Fail },
                new CheckResult { Code = "AV-SIGNATURES", Name = "AV definitions", Category = CheckCategory.Antivirus, RiskLevel = RiskLevel.Medium, Status = CheckStatus.Fail },
                new CheckResult { Code = "UPD-RECENT", Name = "Recent update", Category = CheckCategory.Updates, RiskLevel = RiskLevel.High, Status = CheckStatus.Error },
                new CheckResult { Code = "FW-DOMAIN", Name = "Domain firewall", Category = CheckCategory.Firewall, RiskLevel = RiskLevel.High, Status = CheckStatus.Pass },
                // Newly enabled check failing for the first time => Newly failing
                new CheckResult { Code = "SVC-SMB1", Name = "SMBv1 off", Category = CheckCategory.ServicesAndFeatures, RiskLevel = RiskLevel.Critical, Status = CheckStatus.Fail }
            }
        };

        var comparison = AuditAnalyticsService.CompareAudits(current, previous);

        Assert.Equal(10, comparison.PreviousComputerAuditId);
        Assert.Equal(18, comparison.ScoreDelta);
        Assert.Equal("+18", comparison.ScoreDeltaDisplay);
        Assert.Equal("risk-low", comparison.ScoreDeltaBadgeClass);

        // Fixed: only FW-PUBLIC (UPD-RECENT became Error, so it must NOT be listed as Fixed).
        Assert.Equal(new[] { "fw-public" }, comparison.FixedSinceLastAudit.Select(c => c.Code));

        // Still failing: ACC-GUEST
        Assert.Equal(new[] { "ACC-GUEST" }, comparison.StillFailing.Select(c => c.Code));

        // Newly failing: SVC-SMB1 (Critical) first, then AV-SIGNATURES (Antivirus) before SVC-RDP (Services)
        Assert.Equal(new[] { "SVC-SMB1", "AV-SIGNATURES", "SVC-RDP" }, comparison.NewlyFailing.Select(c => c.Code));
    }

    [Theory]
    [InlineData(50, 68, 18, "+18", "risk-low")]
    [InlineData(85, 75, -10, "-10", "risk-critical")]
    [InlineData(90, 90, 0, "0", "status-error")]
    [InlineData(null, 80, null, "N/A", "status-error")]
    [InlineData(80, null, null, "N/A", "status-error")]
    public void CompareAudits_formats_positive_negative_zero_and_null_score_deltas(
        int? previousScore,
        int? currentScore,
        int? expectedDelta,
        string expectedDisplay,
        string expectedBadge)
    {
        var prev = new ComputerAudit { Id = 1, ComputerId = 1, Status = ComputerAuditStatus.Completed, Score = previousScore };
        var curr = new ComputerAudit { Id = 2, ComputerId = 1, Status = ComputerAuditStatus.Completed, Score = currentScore };

        var cmp = AuditAnalyticsService.CompareAudits(curr, prev);

        Assert.Equal(expectedDelta, cmp.ScoreDelta);
        Assert.Equal(expectedDisplay, cmp.ScoreDeltaDisplay);
        Assert.Equal(expectedBadge, cmp.ScoreDeltaBadgeClass);
    }

    [Fact]
    public void SelectPreviousCompletedAudit_picks_latest_prior_Completed_audit_of_same_computer_ignoring_failures_and_future_runs()
    {
        var t1 = new DateTime(2026, 11, 1, 8, 0, 0, DateTimeKind.Utc);
        var t2 = new DateTime(2026, 11, 1, 9, 0, 0, DateTimeKind.Utc);
        var t3 = new DateTime(2026, 11, 1, 10, 0, 0, DateTimeKind.Utc);
        var t4 = new DateTime(2026, 11, 1, 11, 0, 0, DateTimeKind.Utc);
        var t5 = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);

        var a1 = new ComputerAudit { Id = 1, ComputerId = 7, Status = ComputerAuditStatus.Completed, FinishedAt = t1, Score = 50 };
        var a2 = new ComputerAudit { Id = 2, ComputerId = 7, Status = ComputerAuditStatus.Completed, FinishedAt = t2, Score = 70 };
        var a3Unreachable = new ComputerAudit { Id = 3, ComputerId = 7, Status = ComputerAuditStatus.Unreachable, FinishedAt = t3 };
        var a4Current = new ComputerAudit { Id = 4, ComputerId = 7, Status = ComputerAuditStatus.Completed, FinishedAt = t4, Score = 88 };
        var a5Future = new ComputerAudit { Id = 5, ComputerId = 7, Status = ComputerAuditStatus.Completed, FinishedAt = t5, Score = 100 };
        var otherPc = new ComputerAudit { Id = 6, ComputerId = 99, Status = ComputerAuditStatus.Completed, FinishedAt = t3, Score = 100 };

        var all = new[] { a1, a2, a3Unreachable, a4Current, a5Future, otherPc };

        var prevForA4 = AuditAnalyticsService.SelectPreviousCompletedAudit(a4Current, all);
        Assert.NotNull(prevForA4);
        Assert.Equal(2, prevForA4!.Id);

        // Viewing earliest audit a1 must return null (not future audits a2/a4/a5).
        Assert.Null(AuditAnalyticsService.SelectPreviousCompletedAudit(a1, all));
    }

    [Fact]
    public void BuildPreviousCompletedAuditQuery_generates_valid_SQL_filtering_Completed_status_and_prior_timestamp()
    {
        using var db = CreateModelInspectionContext();
        var current = new ComputerAudit
        {
            Id = 25,
            ComputerId = 4,
            Status = ComputerAuditStatus.Completed,
            FinishedAt = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc)
        };

        var sql = AuditAnalyticsService.BuildPreviousCompletedAuditQuery(db.ComputerAudits, current).ToQueryString();

        Assert.Contains("Completed", sql, StringComparison.Ordinal);
        Assert.Contains("ORDER BY [c].[FinishedAt] DESC, [c].[Id] DESC", sql, StringComparison.Ordinal);
    }

    // ---------- 3. Category Ordering & Failed Check Sorting ----------

    [Fact]
    public void GroupResultsByCategory_always_orders_categories_in_PROJECT_BRIEF_sequence()
    {
        // Feed checks in alphabetical / reversed order to verify we never sort alphabetically by Category name.
        var shuffled = new[]
        {
            new CheckResult { CheckDefinitionId = 16, Code = "SVC-TELNET", Category = CheckCategory.ServicesAndFeatures, Status = CheckStatus.Pass },
            new CheckResult { CheckDefinitionId = 8, Code = "ACC-GUEST", Category = CheckCategory.Accounts, Status = CheckStatus.Fail },
            new CheckResult { CheckDefinitionId = 5, Code = "AV-ENABLED", Category = CheckCategory.Antivirus, Status = CheckStatus.Pass },
            new CheckResult { CheckDefinitionId = 4, Code = "UPD-RECENT", Category = CheckCategory.Updates, Status = CheckStatus.Fail },
            new CheckResult { CheckDefinitionId = 1, Code = "FW-DOMAIN", Category = CheckCategory.Firewall, Status = CheckStatus.Pass }
        };

        var groups = AuditAnalyticsService.GroupResultsByCategory(shuffled);

        Assert.Equal(
            new[]
            {
                CheckCategory.Firewall,
                CheckCategory.Updates,
                CheckCategory.Antivirus,
                CheckCategory.Accounts,
                CheckCategory.ServicesAndFeatures
            },
            groups.Select(g => g.Category));

        Assert.Equal("Services & Features", groups.Last().DisplayName);
    }

    [Fact]
    public void OrderFailedChecksWorstFirst_sorts_Critical_High_Medium_Low_and_excludes_Pass_and_Error()
    {
        var results = new[]
        {
            new CheckResult { Code = "SVC-TELNET", RiskLevel = RiskLevel.Low, Category = CheckCategory.ServicesAndFeatures, Status = CheckStatus.Fail },
            new CheckResult { Code = "ACC-PWLENGTH", RiskLevel = RiskLevel.Medium, Category = CheckCategory.Accounts, Status = CheckStatus.Fail },
            new CheckResult { Code = "FW-DOMAIN", RiskLevel = RiskLevel.High, Category = CheckCategory.Firewall, Status = CheckStatus.Pass },
            new CheckResult { Code = "AV-ENABLED", RiskLevel = RiskLevel.Critical, Category = CheckCategory.Antivirus, Status = CheckStatus.Error },
            new CheckResult { Code = "SVC-SMB1", RiskLevel = RiskLevel.Critical, Category = CheckCategory.ServicesAndFeatures, Status = CheckStatus.Fail },
            new CheckResult { Code = "FW-PRIVATE", RiskLevel = RiskLevel.High, Category = CheckCategory.Firewall, Status = CheckStatus.Fail },
            new CheckResult { Code = "FW-PUBLIC", RiskLevel = RiskLevel.Critical, Category = CheckCategory.Firewall, Status = CheckStatus.Fail }
        };

        var failed = AuditAnalyticsService.OrderFailedChecksWorstFirst(results);

        Assert.Equal(
            new[] { "FW-PUBLIC", "SVC-SMB1", "FW-PRIVATE", "ACC-PWLENGTH", "SVC-TELNET" },
            failed.Select(r => r.Code));
    }

    // ---------- 4. Dashboard Aggregation, Chart Buckets & Attention Sorting ----------

    [Fact]
    public void BuildDashboardSummary_aggregates_KPIs_risk_doughnut_latest_category_failures_and_attention_sorting()
    {
        var tOld = new DateTime(2026, 10, 20, 9, 0, 0, DateTimeKind.Utc);
        var tLatest = new DateTime(2026, 11, 1, 14, 30, 0, DateTimeKind.Utc);

        var computers = new List<Computer>
        {
            new() { Id = 1, Name = "PC-SECURE", HostName = "demo:secure", IsActive = true },
            new() { Id = 2, Name = "PC-CRITICAL-60", HostName = "10.0.0.2", IsActive = true },
            new() { Id = 3, Name = "PC-CRITICAL-40", HostName = "10.0.0.3", IsActive = true },
            new() { Id = 4, Name = "PC-HIGH-75", HostName = "10.0.0.4", IsActive = true },
            new() { Id = 5, Name = "PC-MEDIUM-82", HostName = "10.0.0.5", IsActive = true },
            new() { Id = 6, Name = "PC-UNAUDITED", HostName = "10.0.0.6", IsActive = true }
        };

        // Include an older audit for PC-CRITICAL-40 to ensure only the LATEST completed audit counts toward category failures and KPIs.
        var completedAudits = new List<ComputerAudit>
        {
            new()
            {
                Id = 100, ComputerId = 1, Status = ComputerAuditStatus.Completed, FinishedAt = tOld,
                Score = 100, OverallRisk = null, PassedCount = 16, FailedCount = 0
            },
            new()
            {
                Id = 101, ComputerId = 2, Status = ComputerAuditStatus.Completed, FinishedAt = tOld,
                Score = 60, OverallRisk = RiskLevel.Critical, PassedCount = 10, FailedCount = 2,
                CheckResults =
                {
                    new CheckResult { Code = "FW-PUBLIC", Category = CheckCategory.Firewall, Status = CheckStatus.Fail },
                    new CheckResult { Code = "SVC-SMB1", Category = CheckCategory.ServicesAndFeatures, Status = CheckStatus.Fail }
                }
            },
            new()
            {
                // Older audit on Computer 3 (must be ignored because Id 103 is newer!)
                Id = 90, ComputerId = 3, Status = ComputerAuditStatus.Completed, FinishedAt = tOld.AddDays(-5),
                Score = 95, OverallRisk = RiskLevel.Low,
                CheckResults =
                {
                    new CheckResult { Code = "UPD-RECENT", Category = CheckCategory.Updates, Status = CheckStatus.Fail }
                }
            },
            new()
            {
                Id = 103, ComputerId = 3, Status = ComputerAuditStatus.Completed, FinishedAt = tLatest,
                Score = 40, OverallRisk = RiskLevel.Critical, PassedCount = 6, FailedCount = 3,
                CheckResults =
                {
                    new CheckResult { Code = "FW-DOMAIN", Category = CheckCategory.Firewall, Status = CheckStatus.Fail },
                    new CheckResult { Code = "AV-ENABLED", Category = CheckCategory.Antivirus, Status = CheckStatus.Fail },
                    new CheckResult { Code = "ACC-GUEST", Category = CheckCategory.Accounts, Status = CheckStatus.Fail },
                    new CheckResult { Code = "UPD-RECENT", Category = CheckCategory.Updates, Status = CheckStatus.Pass }
                }
            },
            new()
            {
                Id = 104, ComputerId = 4, Status = ComputerAuditStatus.Completed, FinishedAt = tOld,
                Score = 75, OverallRisk = RiskLevel.High, PassedCount = 13, FailedCount = 1,
                CheckResults =
                {
                    new CheckResult { Code = "FW-PRIVATE", Category = CheckCategory.Firewall, Status = CheckStatus.Fail }
                }
            },
            new()
            {
                Id = 105, ComputerId = 5, Status = ComputerAuditStatus.Completed, FinishedAt = tOld,
                Score = 82, OverallRisk = RiskLevel.Medium, PassedCount = 14, FailedCount = 1,
                CheckResults =
                {
                    new CheckResult { Code = "ACC-LOCKOUT", Category = CheckCategory.Accounts, Status = CheckStatus.Fail }
                }
            }
        };

        var summary = AuditAnalyticsService.BuildDashboardSummary(
            computers,
            completedAudits,
            completedAudits,
            inactiveComputerCount: 1,
            openAlertCount: 3,
            ScoreThresholds.Default);

        // KPIs: 6 active computers; scores = [100, 60, 40, 75, 82] => sum 357 / 5 = 71.4 => 71 (Fair)
        Assert.Equal(6, summary.TotalComputers);
        Assert.Equal(1, summary.InactiveComputers);
        Assert.Equal(71, summary.AverageScore);
        Assert.Equal("Fair", summary.AverageScoreLabel);
        Assert.Equal(3, summary.HighOrCriticalComputers); // 2 Critical + 1 High
        Assert.Equal(3, summary.OpenAlerts);
        Assert.Equal(tLatest, summary.LastAuditAtUtc);

        // Doughnut buckets: [Secure=1, Low=0, Medium=1, High=1, Critical=2, Not audited=1] (sum = 6)
        Assert.Equal(new[] { "Secure", "Low", "Medium", "High", "Critical", "Not audited" }, summary.RiskLabels);
        Assert.Equal(new[] { 1, 0, 1, 1, 2, 1 }, summary.RiskCounts);
        Assert.Equal(6, summary.RiskCounts.Sum());
        Assert.Equal(new[] { "#168653", "#168653", "#E5B72E", "#EC8A3C", "#F45D5B", "#8A94A6" }, summary.RiskColors);

        // Category failures in brief order: Firewall=3, Updates=0 (old audit ignored!), Antivirus=1, Accounts=2, Services & Features=1
        Assert.Equal(
            new[] { "Firewall", "Updates", "Antivirus", "Accounts", "Services & Features" },
            summary.CategoryLabels);
        Assert.Equal(new[] { 3, 0, 1, 2, 1 }, summary.CategoryFailedCounts);

        // Attention table order: Critical (score 40) -> Critical (score 60) -> High (75) -> Medium (82) -> Not audited -> Secure (100)
        Assert.Equal(
            new[] { "PC-CRITICAL-40", "PC-CRITICAL-60", "PC-HIGH-75", "PC-MEDIUM-82", "PC-UNAUDITED", "PC-SECURE" },
            summary.AttentionComputers.Select(r => r.ComputerName));
    }

    // ---------- 5. Authorization: Alerts Acknowledgement (AuditPolicy) & RawJson (ManagePolicy) ----------

    [Fact]
    public async Task Alerts_OnPostAcknowledgeAsync_and_OnPostAcknowledgeAllAsync_return_Forbid_for_Viewer_and_Anonymous()
    {
        using var db = CreateModelInspectionContext();
        var authService = CreateAuthorizationService();
        var activityLog = new ActivityLogService(db);

        foreach (var principal in new[] { UserInRole(AppRoles.Viewer), AnonymousUser() })
        {
            var pageModel = new AlertsIndexModel(db, authService, activityLog)
            {
                PageContext = new PageContext
                {
                    HttpContext = new DefaultHttpContext { User = principal }
                }
            };

            var singleResult = await pageModel.OnPostAcknowledgeAsync(id: 1, tab: "open");
            Assert.IsType<ForbidResult>(singleResult);

            var allResult = await pageModel.OnPostAcknowledgeAllAsync();
            Assert.IsType<ForbidResult>(allResult);
        }
    }

    [Fact]
    public async Task AuditPolicy_allows_Administrator_and_Auditor_for_alert_acknowledgement_and_TryAcknowledgeAlert_is_idempotent()
    {
        var authService = CreateAuthorizationService();
        Assert.True((await authService.AuthorizeAsync(UserInRole(AppRoles.Administrator), AppPolicies.Audit)).Succeeded);
        Assert.True((await authService.AuthorizeAsync(UserInRole(AppRoles.Auditor), AppPolicies.Audit)).Succeeded);
        Assert.False((await authService.AuthorizeAsync(UserInRole(AppRoles.Viewer), AppPolicies.Audit)).Succeeded);

        var alert = new Alert
        {
            Id = 42,
            ComputerId = 1,
            ComputerAuditId = 10,
            Severity = RiskLevel.Critical,
            Message = "SC-LAB-01: 2 Critical findings (score 50)",
            IsAcknowledged = false
        };

        var auditorPrincipal = UserInRole(AppRoles.Auditor, fullName: "Maria Santos");
        var ackTime = new DateTime(2026, 11, 2, 1, 30, 0, DateTimeKind.Utc);

        var changedFirst = AlertsIndexModel.TryAcknowledgeAlert(
            alert,
            AlertsIndexModel.ResolveAcknowledgerName(auditorPrincipal),
            ackTime);

        Assert.True(changedFirst);
        Assert.True(alert.IsAcknowledged);
        Assert.Equal("Maria Santos", alert.AcknowledgedByName);
        Assert.Equal(ackTime, alert.AcknowledgedAt);

        // Second call must be a no-op and preserve original acknowledger and timestamp.
        var changedSecond = AlertsIndexModel.TryAcknowledgeAlert(alert, "Another User", ackTime.AddHours(2));
        Assert.False(changedSecond);
        Assert.Equal("Maria Santos", alert.AcknowledgedByName);
        Assert.Equal(ackTime, alert.AcknowledgedAt);
    }

    [Fact]
    public void ResultModel_exposes_PrettyRawJson_only_when_ManagePolicy_is_satisfied()
    {
        using var db = CreateModelInspectionContext();
        var authService = CreateAuthorizationService();
        var audit = new ComputerAudit
        {
            Id = 5,
            AuditRunId = 1,
            ComputerId = 2,
            Computer = new Computer { Id = 2, Name = "SC-LAB-01", HostName = "demo:weak" },
            Status = ComputerAuditStatus.Completed,
            Score = 50,
            OverallRisk = RiskLevel.Critical,
            RawJson = "{\"computerName\":\"SC-LAB-01\"}"
        };

        var adminModel = new AuditsResultModel(db, authService);
        adminModel.PopulateViewModel(audit, ScoreThresholds.Default, sortOrders: null, canManage: true);
        Assert.NotNull(adminModel.PrettyRawJson);
        Assert.Contains("\"computerName\": \"SC-LAB-01\"", adminModel.PrettyRawJson, StringComparison.Ordinal);

        var auditorOrViewerModel = new AuditsResultModel(db, authService);
        auditorOrViewerModel.PopulateViewModel(audit, ScoreThresholds.Default, sortOrders: null, canManage: false);
        Assert.Null(auditorOrViewerModel.PrettyRawJson);
    }

    [Theory]
    [InlineData(typeof(DashboardIndexModel))]
    [InlineData(typeof(AuditsIndexModel))]
    [InlineData(typeof(AuditsDetailsModel))]
    [InlineData(typeof(AuditsResultModel))]
    [InlineData(typeof(ComputerHistoryModel))]
    [InlineData(typeof(AlertsIndexModel))]
    public void Phase7_read_pages_use_FallbackPolicy_so_all_authenticated_roles_including_Viewer_can_view_them(Type pageModelType)
    {
        var authorizeAttr = pageModelType.GetCustomAttribute<AuthorizeAttribute>(inherit: true);
        Assert.Null(authorizeAttr?.Policy);
        Assert.Null(authorizeAttr?.Roles);
    }

    // ---------- 6. Date-Range Filter, Pagination & Local Chart.js Verification ----------

    [Fact]
    public void ResolveDateRangeUtc_converts_local_calendar_dates_to_UTC_bounds_and_normalizes_inverted_ranges()
    {
        var manilaTz = TimeZoneInfo.CreateCustomTimeZone("Test-UTC+8", TimeSpan.FromHours(8), "UTC+8", "UTC+8");
        var d1 = new DateOnly(2026, 11, 2);
        var d2 = new DateOnly(2026, 11, 5);

        // Pass inverted (d2, d1) to verify automatic normalization.
        var (startUtc, endUtcExclusive, normFrom, normTo) = AuditAnalyticsService.ResolveDateRangeUtc(d2, d1, manilaTz);

        Assert.Equal(d1, normFrom);
        Assert.Equal(d2, normTo);
        // 2026-11-02 00:00:00 +08:00 == 2026-11-01 16:00:00 UTC
        Assert.Equal(new DateTime(2026, 11, 1, 16, 0, 0, DateTimeKind.Utc), startUtc);
        // Exclusive end: 2026-11-06 00:00:00 +08:00 == 2026-11-05 16:00:00 UTC
        Assert.Equal(new DateTime(2026, 11, 5, 16, 0, 0, DateTimeKind.Utc), endUtcExclusive);

        Assert.Equal(1, AuditsIndexModel.CalculateTotalPages(0, 20));
        Assert.Equal(1, AuditsIndexModel.CalculateTotalPages(20, 20));
        Assert.Equal(2, AuditsIndexModel.CalculateTotalPages(21, 20));
        Assert.Equal(3, AuditsIndexModel.CalculateTotalPages(41, 20));
    }

    [Fact]
    public void Chart_pages_reference_local_Chart_js_bundle_and_external_charts_js_with_no_CDN_links()
    {
        var repoRoot = FindRepoRoot();
        var webRoot = Path.Combine(repoRoot, "src", "SecureCheck.Web");

        var dashboardView = File.ReadAllText(Path.Combine(webRoot, "Pages", "Index.cshtml"));
        var historyView = File.ReadAllText(Path.Combine(webRoot, "Pages", "Computers", "History.cshtml"));

        foreach (var view in new[] { dashboardView, historyView })
        {
            Assert.Contains("~/lib/chart.js/dist/chart.umd.js", view, StringComparison.Ordinal);
            Assert.Contains("~/js/charts.js", view, StringComparison.Ordinal);
            Assert.DoesNotContain("https://", view, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("http://", view, StringComparison.OrdinalIgnoreCase);
        }
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

    private static ClaimsPrincipal UserInRole(string role, string? fullName = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, $"{role.ToLowerInvariant()}@securecheck.local"),
            new(ClaimTypes.Role, role)
        };

        if (!string.IsNullOrWhiteSpace(fullName))
        {
            claims.Add(new Claim(AppClaimTypes.FullName, fullName));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Test"));
    }

    private static ClaimsPrincipal AnonymousUser() => new(new ClaimsIdentity());

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SecureCheck.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("Could not find SecureCheck.sln.");
    }
}

