using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>
/// Outcome of evaluating a single CheckDefinition against collected AuditFacts,
/// carrying check definition snapshot fields alongside Actual/Expected/Message details.
/// </summary>
public sealed class CheckOutcome
{
    public int CheckDefinitionId { get; init; }
    public string Code { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public CheckCategory Category { get; init; }
    public RiskLevel RiskLevel { get; init; }
    public int? Threshold { get; init; }
    public string Remediation { get; init; } = string.Empty;

    public CheckStatus Status { get; init; }
    public string? ActualValue { get; init; }
    public string? ExpectedValue { get; init; }
    public string? Message { get; init; }
}

/// <summary>
/// Aggregate result of evaluating all enabled CheckDefinitions for one computer's AuditFacts.
/// </summary>
public sealed class EvaluationResult
{
    public List<CheckOutcome> Outcomes { get; init; } = new();
    public int? Score { get; init; }
    public RiskLevel? OverallRisk { get; init; }
    public int Passed { get; init; }
    public int Failed { get; init; }
    public int Errors { get; init; }
    public int Skipped { get; init; }
}

/// <summary>
/// Pure, stateless evaluation engine that turns collected AuditFacts and enabled CheckDefinitions
/// into per-check Pass/Fail/Error/Skipped outcomes, a weighted 0–100 security score, and overall risk.
/// </summary>
public sealed class AuditEvaluator
{
    /// <summary>
    /// Evaluates enabled checklist definitions against collected computer security facts.
    /// </summary>
    public EvaluationResult Evaluate(
        AuditFacts facts,
        IReadOnlyList<CheckDefinition> enabledChecks,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(enabledChecks);

        var outcomes = new List<CheckOutcome>(enabledChecks.Count);
        var passed = 0;
        var failed = 0;
        var errors = 0;
        var skipped = 0;
        var passWeight = 0;
        var failWeight = 0;
        RiskLevel? overallRisk = null;

        foreach (var check in enabledChecks)
        {
            if (check is null || !check.IsEnabled)
                continue;

            var rule = EvaluateRule(facts, check, now);

            var outcome = new CheckOutcome
            {
                CheckDefinitionId = check.Id,
                Code = check.Code,
                Name = check.Name,
                Category = check.Category,
                RiskLevel = check.RiskLevel,
                Threshold = check.Threshold,
                Remediation = check.Remediation,
                Status = rule.Status,
                ActualValue = rule.ActualValue,
                ExpectedValue = rule.ExpectedValue,
                Message = rule.Message
            };

            outcomes.Add(outcome);

            switch (outcome.Status)
            {
                case CheckStatus.Pass:
                    passed++;
                    passWeight += GetWeight(check.RiskLevel);
                    break;

                case CheckStatus.Fail:
                    failed++;
                    failWeight += GetWeight(check.RiskLevel);
                    if (!overallRisk.HasValue || check.RiskLevel > overallRisk.Value)
                    {
                        overallRisk = check.RiskLevel;
                    }
                    break;

                case CheckStatus.Error:
                    errors++;
                    break;

                case CheckStatus.Skipped:
                    skipped++;
                    break;
            }
        }

        var totalEvaluatedWeight = passWeight + failWeight;
        int? score = totalEvaluatedWeight > 0
            ? (int)Math.Round(100.0 * passWeight / totalEvaluatedWeight, MidpointRounding.AwayFromZero)
            : null;

        return new EvaluationResult
        {
            Outcomes = outcomes,
            Score = score,
            OverallRisk = overallRisk,
            Passed = passed,
            Failed = failed,
            Errors = errors,
            Skipped = skipped
        };
    }

    /// <summary>
    /// Risk weights from PROJECT_BRIEF: Low = 1, Medium = 2, High = 3, Critical = 4.
    /// </summary>
    public static int GetWeight(RiskLevel risk) => risk switch
    {
        RiskLevel.Low => 1,
        RiskLevel.Medium => 2,
        RiskLevel.High => 3,
        RiskLevel.Critical => 4,
        _ => 1
    };

    /// <summary>
    /// Maps a numeric score to its display label and CSS classes using AppSettings thresholds.
    /// </summary>
    public static (string Label, string BadgeClass, string TextClass) DescribeScore(
        int? score,
        int goodMin = 90,
        int fairMin = 70,
        int poorMin = 50)
    {
        if (!score.HasValue)
            return ("Not Evaluated", "status-error", "text-sc-gray");

        if (score.Value >= goodMin)
            return ("Good", "risk-low", "text-sc-green");

        if (score.Value >= fairMin)
            return ("Fair", "risk-medium", "text-sc-yellow");

        if (score.Value >= poorMin)
            return ("Poor", "risk-high", "text-sc-orange");

        return ("Critical", "risk-critical", "text-sc-red");
    }

    private static RuleOutcome EvaluateRule(AuditFacts facts, CheckDefinition check, DateTimeOffset now)
    {
        var normalizedCode = (check.Code ?? string.Empty).Trim().ToUpperInvariant();

        return normalizedCode switch
        {
            "FW-DOMAIN" => EvaluateFirewallProfile(facts.Firewall, "Domain"),
            "FW-PRIVATE" => EvaluateFirewallProfile(facts.Firewall, "Private"),
            "FW-PUBLIC" => EvaluateFirewallProfile(facts.Firewall, "Public"),
            "UPD-RECENT" => EvaluateRecentUpdates(facts.Updates, check.Threshold, now),
            "AV-ENABLED" => EvaluateAntivirusEnabled(facts.Antivirus),
            "AV-REALTIME" => EvaluateAntivirusRealtime(facts.Antivirus),
            "AV-SIGNATURES" => EvaluateAntivirusSignatures(facts.Antivirus, check.Threshold),
            "ACC-GUEST" => EvaluateGuestAccount(facts.Accounts),
            "ACC-ADMINS" => EvaluateAdministratorsCount(facts.Accounts, check.Threshold),
            "ACC-PWLENGTH" => EvaluatePasswordLength(facts.Accounts, check.Threshold),
            "ACC-PWCOMPLEX" => EvaluatePasswordComplexity(facts.Accounts),
            "ACC-LOCKOUT" => EvaluateAccountLockout(facts.Accounts, check.Threshold),
            "SVC-REMOTEREG" => EvaluateRemoteRegistry(facts.ServicesAndFeatures),
            "SVC-RDP" => EvaluateRemoteDesktop(facts.ServicesAndFeatures),
            "SVC-SMB1" => EvaluateSmb1(facts.ServicesAndFeatures),
            "SVC-TELNET" => EvaluateTelnetClient(facts.ServicesAndFeatures),
            _ => RuleOutcome.Skipped($"No evaluation rule is defined for check code '{check.Code}'.")
        };
    }

    // ---------- 1. Firewall rules ----------

    private static RuleOutcome EvaluateFirewallProfile(FirewallFacts? firewall, string profileName)
    {
        if (firewall is null)
            return RuleOutcome.Error("Firewall section was not collected.");

        if (!string.IsNullOrWhiteSpace(firewall.Error))
            return RuleOutcome.Error(firewall.Error);

        if (firewall.Profiles is null)
            return RuleOutcome.Error("Firewall profiles list was not collected.");

        var profile = firewall.Profiles.FirstOrDefault(
            p => p is not null && string.Equals(p.Name?.Trim(), profileName, StringComparison.OrdinalIgnoreCase));

        if (profile?.Enabled is not bool isEnabled)
            return RuleOutcome.Error($"Firewall profile '{profileName}' status could not be read.");

        var actual = isEnabled ? "On" : "Off";
        const string expected = "On";

        return isEnabled
            ? RuleOutcome.Pass(actual, expected, $"{profileName} network firewall profile is turned on.")
            : RuleOutcome.Fail(actual, expected, $"{profileName} network firewall profile is turned off.");
    }

    // ---------- 2. Windows Updates rule ----------

    private static RuleOutcome EvaluateRecentUpdates(UpdatesFacts? updates, int? configuredThreshold, DateTimeOffset now)
    {
        if (configuredThreshold is not int threshold || threshold <= 0)
            return RuleOutcome.Error("Threshold is not configured for check UPD-RECENT.");

        if (updates is null)
            return RuleOutcome.Error("Windows Update section was not collected.");

        if (!string.IsNullOrWhiteSpace(updates.Error))
            return RuleOutcome.Error(updates.Error);

        if (updates.LastInstalledOn is not DateTimeOffset lastInstalled)
            return RuleOutcome.Error("Last installed Windows update date could not be determined.");

        // Floor calendar days elapsed (clamped to 0 if target PC clock is slightly ahead of server).
        var daysAgo = Math.Max(0, (int)Math.Floor((now - lastInstalled).TotalDays));
        var actual = daysAgo == 1 ? "1 day ago" : $"{daysAgo} days ago";
        var expected = $"≤ {threshold} days";
        var kbSuffix = string.IsNullOrWhiteSpace(updates.LatestHotFixId)
            ? string.Empty
            : $" ({updates.LatestHotFixId.Trim()})";

        return daysAgo <= threshold
            ? RuleOutcome.Pass(actual, expected, $"Last Windows update was installed {actual}{kbSuffix}.")
            : RuleOutcome.Fail(actual, expected, $"Last Windows update was installed {actual}{kbSuffix}, exceeding the {threshold}-day threshold.");
    }

    // ---------- 3. Antivirus rules ----------

    private static RuleOutcome EvaluateAntivirusEnabled(AntivirusFacts? antivirus)
    {
        if (antivirus is null)
            return RuleOutcome.Error("Antivirus section was not collected.");

        if (!string.IsNullOrWhiteSpace(antivirus.Error))
            return RuleOutcome.Error(antivirus.Error);

        if (antivirus.AntivirusEnabled is not bool isEnabled)
            return RuleOutcome.Error("Antivirus enabled status could not be read.");

        var actual = isEnabled ? "On" : "Off";
        const string expected = "On";

        return isEnabled
            ? RuleOutcome.Pass(actual, expected, "Antivirus protection is turned on.")
            : RuleOutcome.Fail(actual, expected, "Antivirus protection is turned off.");
    }

    private static RuleOutcome EvaluateAntivirusRealtime(AntivirusFacts? antivirus)
    {
        if (antivirus is null)
            return RuleOutcome.Error("Antivirus section was not collected.");

        if (!string.IsNullOrWhiteSpace(antivirus.Error))
            return RuleOutcome.Error(antivirus.Error);

        if (antivirus.RealTimeProtectionEnabled is not bool isRealtimeOn)
            return RuleOutcome.Error("Real-time virus protection status could not be read.");

        var actual = isRealtimeOn ? "On" : "Off";
        const string expected = "On";

        return isRealtimeOn
            ? RuleOutcome.Pass(actual, expected, "Real-time virus protection is turned on.")
            : RuleOutcome.Fail(actual, expected, "Real-time virus protection is turned off.");
    }

    private static RuleOutcome EvaluateAntivirusSignatures(AntivirusFacts? antivirus, int? configuredThreshold)
    {
        if (configuredThreshold is not int threshold || threshold < 0)
            return RuleOutcome.Error("Threshold is not configured for check AV-SIGNATURES.");

        if (antivirus is null)
            return RuleOutcome.Error("Antivirus section was not collected.");

        if (!string.IsNullOrWhiteSpace(antivirus.Error))
            return RuleOutcome.Error(antivirus.Error);

        if (antivirus.SignatureAgeDays is not int ageDays || ageDays < 0)
            return RuleOutcome.Error("Virus definition signature age could not be read.");

        var actual = ageDays == 1 ? "1 day old" : $"{ageDays} days old";
        var expected = $"≤ {threshold} days";

        return ageDays <= threshold
            ? RuleOutcome.Pass(actual, expected, $"Virus definitions are {actual}.")
            : RuleOutcome.Fail(actual, expected, $"Virus definitions are {actual}, exceeding the {threshold}-day threshold.");
    }

    // ---------- 4. Accounts & Password Policy rules ----------

    private static RuleOutcome EvaluateGuestAccount(AccountsFacts? accounts)
    {
        if (accounts is null)
            return RuleOutcome.Error("Accounts section was not collected.");

        if (!string.IsNullOrWhiteSpace(accounts.Error))
            return RuleOutcome.Error(accounts.Error);

        if (accounts.Guest is null)
            return RuleOutcome.Error("Guest account status was not collected.");

        if (!string.IsNullOrWhiteSpace(accounts.Guest.Error))
            return RuleOutcome.Error(accounts.Guest.Error);

        if (accounts.Guest.Exists is not bool exists)
            return RuleOutcome.Error("Guest account existence could not be determined.");

        const string expected = "Disabled";

        if (!exists)
            return RuleOutcome.Pass("Not present", expected, "Built-in Guest account (SID *-501) is not present.");

        if (accounts.Guest.Enabled is not bool isEnabled)
            return RuleOutcome.Error("Guest account enabled status could not be read.");

        return !isEnabled
            ? RuleOutcome.Pass("Disabled", expected, "Built-in Guest account is disabled.")
            : RuleOutcome.Fail("Enabled", expected, "Built-in Guest account is enabled.");
    }

    private static RuleOutcome EvaluateAdministratorsCount(AccountsFacts? accounts, int? configuredThreshold)
    {
        if (configuredThreshold is not int threshold || threshold <= 0)
            return RuleOutcome.Error("Threshold is not configured for check ACC-ADMINS.");

        if (accounts is null)
            return RuleOutcome.Error("Accounts section was not collected.");

        if (!string.IsNullOrWhiteSpace(accounts.Error))
            return RuleOutcome.Error(accounts.Error);

        if (accounts.Administrators is null)
            return RuleOutcome.Error("Local Administrators group details were not collected.");

        if (!string.IsNullOrWhiteSpace(accounts.Administrators.Error))
            return RuleOutcome.Error(accounts.Administrators.Error);

        if (accounts.Administrators.Count is not int count || count < 0)
            return RuleOutcome.Error("Local Administrators member count could not be read.");

        var actual = count == 1 ? "1 admin" : $"{count} admins";
        var expected = threshold == 1 ? "≤ 1 admin" : $"≤ {threshold} admins";
        var members = accounts.Administrators.Members?
            .Where(m => !string.IsNullOrWhiteSpace(m))
            .Select(m => m.Trim())
            .ToList();
        var membersDetail = members is { Count: > 0 }
            ? $" ({string.Join(", ", members)})"
            : string.Empty;

        return count <= threshold
            ? RuleOutcome.Pass(actual, expected, $"Local Administrators group has {actual}{membersDetail}.")
            : RuleOutcome.Fail(actual, expected, $"Local Administrators group has {actual}{membersDetail}, exceeding the maximum of {threshold}.");
    }

    private static RuleOutcome EvaluatePasswordLength(AccountsFacts? accounts, int? configuredThreshold)
    {
        if (configuredThreshold is not int threshold || threshold <= 0)
            return RuleOutcome.Error("Threshold is not configured for check ACC-PWLENGTH.");

        if (TryGetPasswordPolicyError(accounts, out var policy, out var error))
            return RuleOutcome.Error(error);

        if (policy.MinimumPasswordLength is not int minLength || minLength < 0)
            return RuleOutcome.Error("Minimum password length policy could not be read.");

        var actual = minLength == 1 ? "1 character" : $"{minLength} characters";
        var expected = $"≥ {threshold} characters";

        return minLength >= threshold
            ? RuleOutcome.Pass(actual, expected, $"Minimum password length is {actual}.")
            : RuleOutcome.Fail(actual, expected, $"Minimum password length is {actual} (at least {threshold} characters required).");
    }

    private static RuleOutcome EvaluatePasswordComplexity(AccountsFacts? accounts)
    {
        if (TryGetPasswordPolicyError(accounts, out var policy, out var error))
            return RuleOutcome.Error(error);

        if (policy.PasswordComplexity is not int complexity)
            return RuleOutcome.Error("Password complexity policy could not be read.");

        var isComplex = complexity == 1;
        var actual = isComplex ? "On" : "Off";
        const string expected = "On";

        return isComplex
            ? RuleOutcome.Pass(actual, expected, "Password complexity requirement is turned on.")
            : RuleOutcome.Fail(actual, expected, "Password complexity requirement is turned off.");
    }

    private static RuleOutcome EvaluateAccountLockout(AccountsFacts? accounts, int? configuredThreshold)
    {
        if (configuredThreshold is not int threshold || threshold <= 0)
            return RuleOutcome.Error("Threshold is not configured for check ACC-LOCKOUT.");

        if (TryGetPasswordPolicyError(accounts, out var policy, out var error))
            return RuleOutcome.Error(error);

        if (policy.LockoutBadCount is not int lockoutCount || lockoutCount < 0)
            return RuleOutcome.Error("Account lockout threshold could not be read.");

        var expected = $"1–{threshold} attempts";

        if (lockoutCount == 0)
            return RuleOutcome.Fail("Disabled (0)", expected, "Account lockout policy is disabled (0 failed attempts).");

        var actual = lockoutCount == 1 ? "1 attempt" : $"{lockoutCount} attempts";

        return lockoutCount <= threshold
            ? RuleOutcome.Pass(actual, expected, $"Account lockout triggers after {actual}.")
            : RuleOutcome.Fail(actual, expected, $"Account lockout triggers after {actual}, exceeding the maximum of {threshold} failed attempts.");
    }

    private static bool TryGetPasswordPolicyError(
        AccountsFacts? accounts,
        out PasswordPolicyFacts policy,
        out string error)
    {
        policy = null!;

        if (accounts is null)
        {
            error = "Accounts section was not collected.";
            return true;
        }

        if (!string.IsNullOrWhiteSpace(accounts.Error))
        {
            error = accounts.Error;
            return true;
        }

        if (accounts.PasswordPolicy is null)
        {
            error = "Password policy details were not collected.";
            return true;
        }

        if (!string.IsNullOrWhiteSpace(accounts.PasswordPolicy.Error))
        {
            error = accounts.PasswordPolicy.Error;
            return true;
        }

        policy = accounts.PasswordPolicy;
        error = string.Empty;
        return false;
    }

    // ---------- 5. Services and Windows Optional Features rules ----------

    private static RuleOutcome EvaluateRemoteRegistry(ServicesAndFeaturesFacts? services)
    {
        if (services is null)
            return RuleOutcome.Error("Services and features section was not collected.");

        if (!string.IsNullOrWhiteSpace(services.Error))
            return RuleOutcome.Error(services.Error);

        if (services.RemoteRegistry is null)
            return RuleOutcome.Error("Remote Registry service details were not collected.");

        if (!string.IsNullOrWhiteSpace(services.RemoteRegistry.Error))
            return RuleOutcome.Error(services.RemoteRegistry.Error);

        if (services.RemoteRegistry.Exists is not bool exists)
            return RuleOutcome.Error("Remote Registry service existence could not be determined.");

        const string expected = "Not running, not Automatic";

        if (!exists)
            return RuleOutcome.Pass("Not installed", expected, "Remote Registry service is not installed.");

        var status = services.RemoteRegistry.Status?.Trim();
        var startType = services.RemoteRegistry.StartType?.Trim();

        if (string.IsNullOrWhiteSpace(status) || string.IsNullOrWhiteSpace(startType))
            return RuleOutcome.Error("Remote Registry service status or startup type could not be read.");

        var isRunning = status.Equals("Running", StringComparison.OrdinalIgnoreCase);
        var isAutomatic = startType.StartsWith("Automatic", StringComparison.OrdinalIgnoreCase);
        var actual = $"{status} ({startType})";

        return !isRunning && !isAutomatic
            ? RuleOutcome.Pass(actual, expected, $"Remote Registry service is {status} with startup type {startType}.")
            : RuleOutcome.Fail(actual, expected, $"Remote Registry service is {status} with startup type {startType}.");
    }

    private static RuleOutcome EvaluateRemoteDesktop(ServicesAndFeaturesFacts? services)
    {
        if (services is null)
            return RuleOutcome.Error("Services and features section was not collected.");

        if (!string.IsNullOrWhiteSpace(services.Error))
            return RuleOutcome.Error(services.Error);

        if (services.RdpEnabled is not bool rdpEnabled)
            return RuleOutcome.Error("Remote Desktop status could not be read.");

        var actual = rdpEnabled ? "On" : "Off";
        const string expected = "Off";

        return !rdpEnabled
            ? RuleOutcome.Pass(actual, expected, "Remote Desktop connections are turned off.")
            : RuleOutcome.Fail(actual, expected, "Remote Desktop connections are turned on.");
    }

    private static RuleOutcome EvaluateSmb1(ServicesAndFeaturesFacts? services)
    {
        if (services is null)
            return RuleOutcome.Error("Services and features section was not collected.");

        if (!string.IsNullOrWhiteSpace(services.Error))
            return RuleOutcome.Error(services.Error);

        if (services.Smb1 is null)
            return RuleOutcome.Error("SMBv1 status was not collected.");

        if (!string.IsNullOrWhiteSpace(services.Smb1.Error))
            return RuleOutcome.Error(services.Smb1.Error);

        if (services.Smb1.ServerProtocolEnabled is not bool protocolEnabled ||
            string.IsNullOrWhiteSpace(services.Smb1.FeatureState))
        {
            return RuleOutcome.Error("SMBv1 server protocol or optional feature state could not be read.");
        }

        var featureState = services.Smb1.FeatureState.Trim();
        var featureEnabled = IsWindowsFeatureEnabled(featureState);
        var protoLabel = protocolEnabled ? "On" : "Off";
        var actual = $"Protocol {protoLabel}, Feature {featureState}";
        const string expected = "Protocol Off, Feature Disabled";

        return !protocolEnabled && !featureEnabled
            ? RuleOutcome.Pass(actual, expected, $"SMBv1 server protocol is disabled and SMB1Protocol feature is {featureState}.")
            : RuleOutcome.Fail(actual, expected, $"SMBv1 is enabled (server protocol: {protoLabel}, feature state: {featureState}).");
    }

    private static RuleOutcome EvaluateTelnetClient(ServicesAndFeaturesFacts? services)
    {
        if (services is null)
            return RuleOutcome.Error("Services and features section was not collected.");

        if (!string.IsNullOrWhiteSpace(services.Error))
            return RuleOutcome.Error(services.Error);

        if (services.TelnetClient is null)
            return RuleOutcome.Error("Telnet Client feature status was not collected.");

        if (!string.IsNullOrWhiteSpace(services.TelnetClient.Error))
            return RuleOutcome.Error(services.TelnetClient.Error);

        if (string.IsNullOrWhiteSpace(services.TelnetClient.FeatureState))
            return RuleOutcome.Error("Telnet Client optional feature state could not be read.");

        var featureState = services.TelnetClient.FeatureState.Trim();
        var isEnabled = IsWindowsFeatureEnabled(featureState);
        const string expected = "Disabled";

        return !isEnabled
            ? RuleOutcome.Pass(featureState, expected, $"Telnet Client feature state is {featureState}.")
            : RuleOutcome.Fail(featureState, expected, $"Telnet Client feature is {featureState}.");
    }

    private static bool IsWindowsFeatureEnabled(string featureState) =>
        featureState.Equals("Enabled", StringComparison.OrdinalIgnoreCase) ||
        featureState.Equals("EnablePending", StringComparison.OrdinalIgnoreCase);

    private readonly record struct RuleOutcome(
        CheckStatus Status,
        string? ActualValue,
        string? ExpectedValue,
        string Message)
    {
        public static RuleOutcome Pass(string actual, string expected, string message) =>
            new(CheckStatus.Pass, actual, expected, message);

        public static RuleOutcome Fail(string actual, string expected, string message) =>
            new(CheckStatus.Fail, actual, expected, message);

        public static RuleOutcome Error(string message) =>
            new(CheckStatus.Error, null, null, TruncateMessage(message));

        public static RuleOutcome Skipped(string message) =>
            new(CheckStatus.Skipped, null, null, TruncateMessage(message));

        private static string TruncateMessage(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return "Fact could not be collected.";

            var trimmed = text.Trim();
            return trimmed.Length <= 1000 ? trimmed : trimmed[..997] + "...";
        }
    }
}

