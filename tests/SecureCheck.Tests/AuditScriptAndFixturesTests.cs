using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SecureCheck.Tests;

public class AuditScriptAndFixturesTests
{
    private static readonly string[] ExpectedTopLevelKeys =
    [
        "schemaVersion",
        "computerName",
        "collectedAt",
        "os",
        "firewall",
        "updates",
        "antivirus",
        "accounts",
        "servicesAndFeatures"
    ];

    [Fact]
    public void Audit_script_is_configured_with_PreserveNewest_and_copied_to_output_directory()
    {
        var repoRoot = FindRepoRoot();
        var csprojPath = Path.Combine(repoRoot, "src", "SecureCheck.Web", "SecureCheck.Web.csproj");
        var sourceScriptPath = Path.Combine(repoRoot, "src", "SecureCheck.Web", "Scripts", "Invoke-SecureCheckAudit.ps1");
        var outputScriptPath = Path.Combine(AppContext.BaseDirectory, "Scripts", "Invoke-SecureCheckAudit.ps1");

        Assert.True(File.Exists(sourceScriptPath), $"Missing source script: {sourceScriptPath}");
        Assert.True(File.Exists(outputScriptPath), $"Audit script was not copied to output folder: {outputScriptPath}");

        var csprojText = File.ReadAllText(csprojPath);
        Assert.Contains("Invoke-SecureCheckAudit.ps1", csprojText);
        Assert.Contains(@"Scripts\Fixtures\**\*.json", csprojText);
        Assert.Contains("PreserveNewest", csprojText);

        Assert.Equal(File.ReadAllText(sourceScriptPath), File.ReadAllText(outputScriptPath));
    }

    [Fact]
    public void Scripts_README_documents_local_laptop_and_optional_remote_testing()
    {
        var readmePath = Path.Combine(FindRepoRoot(), "src", "SecureCheck.Web", "Scripts", "README.md");

        Assert.True(File.Exists(readmePath), $"Missing Scripts README: {readmePath}");

        var content = File.ReadAllText(readmePath);
        Assert.Contains("powershell -ExecutionPolicy Bypass -File", content);
        Assert.Contains("Invoke-SecureCheckAudit.ps1", content);
        Assert.Contains("Invoke-Command", content);
    }

    [Theory]
    [InlineData("secure-pc.json")]
    [InlineData("weak-pc.json")]
    [InlineData("partial-error.json")]
    public void Fixture_is_copied_to_both_test_and_web_Scripts_Fixtures_output_and_conforms_to_contract(string fileName)
    {
        var testOutputPath = Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);
        var webOutputPath = Path.Combine(AppContext.BaseDirectory, "Scripts", "Fixtures", fileName);
        var webSourcePath = Path.Combine(FindRepoRoot(), "src", "SecureCheck.Web", "Scripts", "Fixtures", fileName);

        Assert.True(File.Exists(testOutputPath), $"Test fixture not copied to output directory: {testOutputPath}");
        Assert.True(File.Exists(webSourcePath), $"Web fixture missing from Scripts/Fixtures: {webSourcePath}");
        Assert.True(File.Exists(webOutputPath), $"Web fixture not copied to Scripts/Fixtures output directory: {webOutputPath}");

        var testJson = File.ReadAllText(testOutputPath);
        var webJson = File.ReadAllText(webOutputPath);
        Assert.Equal(testJson.Trim(), webJson.Trim(), ignoreLineEndingDifferences: true);

        using var doc = JsonDocument.Parse(testJson);
        ValidateAuditJsonContract(doc.RootElement, fileName);
    }

    [Fact]
    public void Live_local_execution_in_Windows_PowerShell_5_1_finishes_under_15s_with_clean_non_admin_fallbacks()
    {
        var outputScriptPath = Path.Combine(AppContext.BaseDirectory, "Scripts", "Invoke-SecureCheckAudit.ps1");
        var tempDir = Path.GetTempPath();
        var existingTempFiles = Directory.GetFiles(tempDir, "sc_secpol_*.inf").ToHashSet(StringComparer.OrdinalIgnoreCase);

        var sw = Stopwatch.StartNew();
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{outputScriptPath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;

        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        Assert.True(proc.WaitForExit(15_000), "Invoke-SecureCheckAudit.ps1 exceeded the 15-second budget.");
        sw.Stop();

        Assert.True(sw.Elapsed.TotalSeconds < 15.0, $"Expected < 15s, took {sw.Elapsed.TotalSeconds:F2}s.");
        Assert.True(proc.ExitCode == 0, $"Invoke-SecureCheckAudit.ps1 exited with {proc.ExitCode}. stderr: {stderr}");
        Assert.True(string.IsNullOrWhiteSpace(stderr), $"Expected empty stderr, got: {stderr}");

        var nonEmptyLines = stdout
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        Assert.Single(nonEmptyLines);

        using var doc = JsonDocument.Parse(nonEmptyLines[0]);
        var root = doc.RootElement;
        ValidateAuditJsonContract(root, "live-ps51");

        // Verify non-admin fallbacks populate real values rather than failing with elevation errors:
        var pwPolicy = root.GetProperty("accounts").GetProperty("passwordPolicy");
        Assert.False(pwPolicy.TryGetProperty("error", out var pwErr) && pwErr.ValueKind != JsonValueKind.Null,
            "passwordPolicy should succeed via secedit or net accounts fallback without error.");
        Assert.NotEqual(JsonValueKind.Null, pwPolicy.GetProperty("minimumPasswordLength").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, pwPolicy.GetProperty("passwordComplexity").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, pwPolicy.GetProperty("lockoutBadCount").ValueKind);

        var smb1 = root.GetProperty("servicesAndFeatures").GetProperty("smb1");
        Assert.False(smb1.TryGetProperty("error", out var smbErr) && smbErr.ValueKind != JsonValueKind.Null,
            "smb1 should succeed via cmdlet or registry/srv.sys fallback without elevation error.");
        Assert.NotEqual(JsonValueKind.Null, smb1.GetProperty("serverProtocolEnabled").ValueKind);
        Assert.NotEqual(JsonValueKind.Null, smb1.GetProperty("featureState").ValueKind);

        var telnet = root.GetProperty("servicesAndFeatures").GetProperty("telnetClient");
        Assert.False(telnet.TryGetProperty("error", out var telnetErr) && telnetErr.ValueKind != JsonValueKind.Null,
            "telnetClient should succeed via DISM or System32\\telnet.exe fallback without elevation error.");
        Assert.NotEqual(JsonValueKind.Null, telnet.GetProperty("featureState").ValueKind);

        var remainingTempFiles = Directory.GetFiles(tempDir, "sc_secpol_*.inf")
            .Where(f => !existingTempFiles.Contains(f))
            .ToList();
        Assert.Empty(remainingTempFiles);
    }

    [Fact]
    public void Secure_pc_fixture_contains_healthy_values_for_all_16_checks()
    {
        using var doc = LoadFixture("secure-pc.json");
        var root = doc.RootElement;

        var collectedAt = DateTimeOffset.Parse(root.GetProperty("collectedAt").GetString()!, CultureInfo.InvariantCulture);

        Assert.All(
            root.GetProperty("firewall").GetProperty("profiles").EnumerateArray(),
            p => Assert.True(p.GetProperty("enabled").GetBoolean()));

        var lastUpdate = DateTimeOffset.Parse(
            root.GetProperty("updates").GetProperty("lastInstalledOn").GetString()!,
            CultureInfo.InvariantCulture);
        Assert.True((collectedAt - lastUpdate).TotalDays <= 30);

        var av = root.GetProperty("antivirus");
        Assert.Equal(JsonValueKind.Null, av.GetProperty("error").ValueKind);
        Assert.True(av.GetProperty("antivirusEnabled").GetBoolean());
        Assert.True(av.GetProperty("realTimeProtectionEnabled").GetBoolean());
        Assert.True(av.GetProperty("signatureAgeDays").GetInt32() <= 7);

        var accounts = root.GetProperty("accounts");
        Assert.False(accounts.GetProperty("guest").GetProperty("enabled").GetBoolean());
        Assert.True(accounts.GetProperty("administrators").GetProperty("count").GetInt32() <= 2);

        var pw = accounts.GetProperty("passwordPolicy");
        Assert.True(pw.GetProperty("minimumPasswordLength").GetInt32() >= 8);
        Assert.Equal(1, pw.GetProperty("passwordComplexity").GetInt32());
        Assert.InRange(pw.GetProperty("lockoutBadCount").GetInt32(), 1, 10);

        var svc = root.GetProperty("servicesAndFeatures");
        var rr = svc.GetProperty("remoteRegistry");
        Assert.NotEqual("Running", rr.GetProperty("status").GetString());
        Assert.NotEqual("Automatic", rr.GetProperty("startType").GetString());
        Assert.False(svc.GetProperty("rdpEnabled").GetBoolean());
        Assert.False(svc.GetProperty("smb1").GetProperty("serverProtocolEnabled").GetBoolean());
        Assert.NotEqual("Enabled", svc.GetProperty("smb1").GetProperty("featureState").GetString());
        Assert.NotEqual("Enabled", svc.GetProperty("telnetClient").GetProperty("featureState").GetString());
    }

    [Fact]
    public void Weak_pc_fixture_contains_expected_failing_facts()
    {
        using var doc = LoadFixture("weak-pc.json");
        var root = doc.RootElement;

        var collectedAt = DateTimeOffset.Parse(root.GetProperty("collectedAt").GetString()!, CultureInfo.InvariantCulture);

        var publicProfile = root.GetProperty("firewall").GetProperty("profiles")
            .EnumerateArray()
            .Single(p => p.GetProperty("name").GetString() == "Public");
        Assert.False(publicProfile.GetProperty("enabled").GetBoolean());

        var lastUpdate = DateTimeOffset.Parse(
            root.GetProperty("updates").GetProperty("lastInstalledOn").GetString()!,
            CultureInfo.InvariantCulture);
        Assert.InRange((collectedAt - lastUpdate).TotalDays, 89.0, 91.0);

        var accounts = root.GetProperty("accounts");
        Assert.True(accounts.GetProperty("guest").GetProperty("enabled").GetBoolean());

        var pw = accounts.GetProperty("passwordPolicy");
        Assert.Equal(0, pw.GetProperty("minimumPasswordLength").GetInt32());
        Assert.Equal(0, pw.GetProperty("passwordComplexity").GetInt32());
        Assert.Equal(0, pw.GetProperty("lockoutBadCount").GetInt32());

        var svc = root.GetProperty("servicesAndFeatures");
        Assert.True(svc.GetProperty("smb1").GetProperty("serverProtocolEnabled").GetBoolean());
        Assert.Equal("Enabled", svc.GetProperty("smb1").GetProperty("featureState").GetString());
        Assert.Equal("Enabled", svc.GetProperty("telnetClient").GetProperty("featureState").GetString());
    }

    [Fact]
    public void Partial_error_fixture_isolates_antivirus_error_and_leaves_other_sections_healthy()
    {
        using var doc = LoadFixture("partial-error.json");
        var root = doc.RootElement;

        var av = root.GetProperty("antivirus");
        Assert.False(string.IsNullOrWhiteSpace(av.GetProperty("error").GetString()));
        Assert.Equal(JsonValueKind.Null, av.GetProperty("antivirusEnabled").ValueKind);
        Assert.Equal(JsonValueKind.Null, av.GetProperty("realTimeProtectionEnabled").ValueKind);
        Assert.Equal(JsonValueKind.Null, av.GetProperty("signatureAgeDays").ValueKind);
        Assert.Equal(JsonValueKind.Null, av.GetProperty("signatureLastUpdated").ValueKind);

        Assert.Equal(JsonValueKind.Null, root.GetProperty("firewall").GetProperty("error").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("updates").GetProperty("error").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("accounts").GetProperty("error").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("servicesAndFeatures").GetProperty("error").ValueKind);
    }

    [Fact]
    public void Audit_script_parses_cleanly_in_Windows_PowerShell_5_1_and_is_strictly_read_only()
    {
        var scriptPath = Path.Combine(FindRepoRoot(), "src", "SecureCheck.Web", "Scripts", "Invoke-SecureCheckAudit.ps1");

        var inspectorScript = $@"
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{scriptPath.Replace("'", "''")}', [ref]$tokens, [ref]$parseErrors)

$commands = @($ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandAst] }}, $true))
$commandNames = @($commands | ForEach-Object {{ $_.GetCommandName() }} | Where-Object {{ $null -ne $_ }})

$params = @($ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.CommandParameterAst] }}, $true))
$paramNames = @($params | ForEach-Object {{ $_.ParameterName }})

$tryBlocks = @($ast.FindAll({{ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] }}, $true))
$finallyBlocks = @($tryBlocks | Where-Object {{ $null -ne $_.Finally }})

$convertToJsonCmds = @($commands | Where-Object {{ $_.GetCommandName() -ieq 'ConvertTo-Json' }})

[ordered]@{{
    psMajor = [int]$PSVersionTable.PSVersion.Major
    psMinor = [int]$PSVersionTable.PSVersion.Minor
    parseErrorCount = [int]$parseErrors.Count
    parseErrors = @($parseErrors | ForEach-Object {{ $_.ToString() }})
    commandNames = $commandNames
    paramNames = $paramNames
    tryCount = [int]$tryBlocks.Count
    finallyCount = [int]$finallyBlocks.Count
    convertToJsonCount = [int]$convertToJsonCmds.Count
    convertToJsonText = if ($convertToJsonCmds.Count -eq 1) {{ $convertToJsonCmds[0].Extent.Text }} else {{ '' }}
}} | ConvertTo-Json -Depth 4 -Compress
";

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(inspectorScript));
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        })!;

        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        Assert.True(proc.WaitForExit(15_000), "powershell.exe AST parser timed out.");
        Assert.True(proc.ExitCode == 0, $"powershell.exe failed (exit {proc.ExitCode}): {stderr}");

        using var resultDoc = JsonDocument.Parse(stdout.Trim());
        var res = resultDoc.RootElement;

        Assert.Equal(5, res.GetProperty("psMajor").GetInt32());
        Assert.Equal(1, res.GetProperty("psMinor").GetInt32());

        var parseErrors = res.GetProperty("parseErrors").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.True(res.GetProperty("parseErrorCount").GetInt32() == 0, "PS 5.1 parse errors: " + string.Join(" | ", parseErrors));

        var commandNames = res.GetProperty("commandNames")
            .EnumerateArray()
            .Select(c => c.GetString()!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Must never emit extra console/formatted output or mutate system settings.
        Assert.DoesNotContain("Write-Host", commandNames);
        Assert.DoesNotContain("Write-Output", commandNames);
        Assert.DoesNotContain("Out-Host", commandNames);
        Assert.DoesNotContain("Format-Table", commandNames);
        Assert.DoesNotContain("Format-List", commandNames);
        Assert.DoesNotContain("Format-Wide", commandNames);
        Assert.DoesNotContain("Set-NetFirewallProfile", commandNames);
        Assert.DoesNotContain("Set-MpPreference", commandNames);
        Assert.DoesNotContain("Set-Service", commandNames);
        Assert.DoesNotContain("Stop-Service", commandNames);
        Assert.DoesNotContain("Start-Service", commandNames);
        Assert.DoesNotContain("Set-ItemProperty", commandNames);
        Assert.DoesNotContain("New-ItemProperty", commandNames);
        Assert.DoesNotContain("Set-SmbServerConfiguration", commandNames);
        Assert.DoesNotContain("Enable-WindowsOptionalFeature", commandNames);
        Assert.DoesNotContain("Disable-WindowsOptionalFeature", commandNames);

        var paramNames = res.GetProperty("paramNames")
            .EnumerateArray()
            .Select(p => p.GetString()!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Disallow PS 7-only cmdlet parameters so script works identically in PS 5.1 and PS 7.
        Assert.DoesNotContain("Parallel", paramNames);
        Assert.DoesNotContain("AsHashtable", paramNames);
        Assert.DoesNotContain("AsByteStream", paramNames);

        Assert.True(res.GetProperty("tryCount").GetInt32() >= 11, "Expected isolated try/catch blocks for all sections and sub-parts.");
        Assert.True(res.GetProperty("finallyCount").GetInt32() >= 1, "Expected a finally block for secedit temp file cleanup.");

        Assert.Equal(1, res.GetProperty("convertToJsonCount").GetInt32());
        var convertText = res.GetProperty("convertToJsonText").GetString()!;
        Assert.Contains("-Depth 6", convertText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("-Compress", convertText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Audit_script_implements_SID_lookups_non_admin_fallbacks_secedit_cleanup_and_ISO_dates()
    {
        var scriptPath = Path.Combine(FindRepoRoot(), "src", "SecureCheck.Web", "Scripts", "Invoke-SecureCheckAudit.ps1");
        var script = File.ReadAllText(scriptPath);

        // SID-based lookups (locale-independent) + ADSI fallback
        Assert.Contains("*-501", script, StringComparison.Ordinal);
        Assert.Contains("S-1-5-32-544", script, StringComparison.Ordinal);
        Assert.Contains("WinNT://", script, StringComparison.Ordinal);

        // Windows Update COM fallback
        Assert.Contains("Microsoft.Update.Session", script, StringComparison.Ordinal);
        Assert.Contains("WindowsUpdateHistory", script, StringComparison.Ordinal);

        // secedit unique temp filename + cleanup + non-admin `net accounts` fallback
        Assert.Contains("secedit.exe", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[guid]::NewGuid()", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Remove-Item", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("net.exe accounts", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("'net accounts'", script, StringComparison.Ordinal);

        // SMB1 & Telnet non-admin fallbacks
        Assert.Contains(@"LanmanServer\Parameters", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"System32\drivers\srv.sys", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"System32\telnet.exe", script, StringComparison.OrdinalIgnoreCase);

        // ISO 8601 round-trip ("o") date formatting
        Assert.Contains(".ToString('o')", script, StringComparison.Ordinal);
    }

    private static void ValidateAuditJsonContract(JsonElement root, string sourceLabel)
    {
        Assert.Equal(JsonValueKind.Object, root.ValueKind);

        AssertExactKeys(root, ExpectedTopLevelKeys, $"{sourceLabel}:root");
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("computerName").GetString()));
        AssertIsoTimestamp(root.GetProperty("collectedAt"), $"{sourceLabel}:collectedAt");

        // os
        var os = root.GetProperty("os");
        AssertExactKeys(os, ["caption", "version", "psVersion", "psMajor"], $"{sourceLabel}:os", optionalKeys: ["error"]);
        AssertStringOrNull(os.GetProperty("caption"));
        AssertStringOrNull(os.GetProperty("version"));
        Assert.False(string.IsNullOrWhiteSpace(os.GetProperty("psVersion").GetString()));
        Assert.True(os.GetProperty("psMajor").GetInt32() >= 5);

        // firewall
        var firewall = root.GetProperty("firewall");
        AssertExactKeys(firewall, ["error", "profiles"], $"{sourceLabel}:firewall");
        AssertStringOrNull(firewall.GetProperty("error"));
        var profiles = firewall.GetProperty("profiles");
        Assert.Equal(JsonValueKind.Array, profiles.ValueKind);
        if (firewall.GetProperty("error").ValueKind == JsonValueKind.Null)
        {
            Assert.Equal(3, profiles.GetArrayLength());
            foreach (var profile in profiles.EnumerateArray())
            {
                AssertExactKeys(profile, ["name", "enabled"], $"{sourceLabel}:firewall.profiles[]");
                Assert.Contains(profile.GetProperty("name").GetString(), new[] { "Domain", "Private", "Public" });
                AssertBool(profile.GetProperty("enabled"));
            }
        }

        // updates
        var updates = root.GetProperty("updates");
        AssertExactKeys(updates, ["error", "lastInstalledOn", "latestHotFixId", "hotFixCount", "source"], $"{sourceLabel}:updates");
        AssertStringOrNull(updates.GetProperty("error"));
        if (updates.GetProperty("lastInstalledOn").ValueKind != JsonValueKind.Null)
            AssertIsoTimestamp(updates.GetProperty("lastInstalledOn"), $"{sourceLabel}:updates.lastInstalledOn");
        AssertStringOrNull(updates.GetProperty("latestHotFixId"));
        AssertIntOrNull(updates.GetProperty("hotFixCount"));
        AssertStringOrNull(updates.GetProperty("source"));

        // antivirus
        var antivirus = root.GetProperty("antivirus");
        AssertExactKeys(
            antivirus,
            ["error", "antivirusEnabled", "realTimeProtectionEnabled", "signatureAgeDays", "signatureLastUpdated"],
            $"{sourceLabel}:antivirus");
        AssertStringOrNull(antivirus.GetProperty("error"));
        AssertBoolOrNull(antivirus.GetProperty("antivirusEnabled"));
        AssertBoolOrNull(antivirus.GetProperty("realTimeProtectionEnabled"));
        AssertIntOrNull(antivirus.GetProperty("signatureAgeDays"));
        if (antivirus.GetProperty("signatureLastUpdated").ValueKind != JsonValueKind.Null)
            AssertIsoTimestamp(antivirus.GetProperty("signatureLastUpdated"), $"{sourceLabel}:antivirus.signatureLastUpdated");

        // accounts
        var accounts = root.GetProperty("accounts");
        AssertExactKeys(accounts, ["error", "guest", "administrators", "passwordPolicy"], $"{sourceLabel}:accounts");
        AssertStringOrNull(accounts.GetProperty("error"));

        var guest = accounts.GetProperty("guest");
        AssertExactKeys(guest, ["exists", "enabled"], $"{sourceLabel}:accounts.guest", optionalKeys: ["error"]);
        AssertBoolOrNull(guest.GetProperty("exists"));
        AssertBoolOrNull(guest.GetProperty("enabled"));

        var admins = accounts.GetProperty("administrators");
        AssertExactKeys(admins, ["count", "members"], $"{sourceLabel}:accounts.administrators", optionalKeys: ["error"]);
        AssertIntOrNull(admins.GetProperty("count"));
        Assert.Equal(JsonValueKind.Array, admins.GetProperty("members").ValueKind);

        var pwPolicy = accounts.GetProperty("passwordPolicy");
        AssertExactKeys(
            pwPolicy,
            ["minimumPasswordLength", "passwordComplexity", "lockoutBadCount", "source"],
            $"{sourceLabel}:accounts.passwordPolicy",
            optionalKeys: ["error"]);
        AssertIntOrNull(pwPolicy.GetProperty("minimumPasswordLength"));
        AssertIntOrNull(pwPolicy.GetProperty("passwordComplexity"));
        AssertIntOrNull(pwPolicy.GetProperty("lockoutBadCount"));
        Assert.Contains(pwPolicy.GetProperty("source").GetString(), new[] { "secedit", "net accounts" });

        // servicesAndFeatures
        var svc = root.GetProperty("servicesAndFeatures");
        AssertExactKeys(
            svc,
            ["error", "remoteRegistry", "rdpEnabled", "smb1", "telnetClient"],
            $"{sourceLabel}:servicesAndFeatures");
        AssertStringOrNull(svc.GetProperty("error"));
        AssertBoolOrNull(svc.GetProperty("rdpEnabled"));

        var remoteRegistry = svc.GetProperty("remoteRegistry");
        AssertExactKeys(
            remoteRegistry,
            ["exists", "status", "startType"],
            $"{sourceLabel}:servicesAndFeatures.remoteRegistry",
            optionalKeys: ["error"]);
        AssertBoolOrNull(remoteRegistry.GetProperty("exists"));
        AssertStringOrNull(remoteRegistry.GetProperty("status"));
        AssertStringOrNull(remoteRegistry.GetProperty("startType"));

        var smb1 = svc.GetProperty("smb1");
        AssertExactKeys(
            smb1,
            ["serverProtocolEnabled", "featureState"],
            $"{sourceLabel}:servicesAndFeatures.smb1",
            optionalKeys: ["error"]);
        AssertBoolOrNull(smb1.GetProperty("serverProtocolEnabled"));
        AssertStringOrNull(smb1.GetProperty("featureState"));

        var telnet = svc.GetProperty("telnetClient");
        AssertExactKeys(
            telnet,
            ["featureState"],
            $"{sourceLabel}:servicesAndFeatures.telnetClient",
            optionalKeys: ["error"]);
        AssertStringOrNull(telnet.GetProperty("featureState"));
    }

    private static JsonDocument LoadFixture(string fileName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", fileName);
        return JsonDocument.Parse(File.ReadAllText(path));
    }

    private static void AssertExactKeys(
        JsonElement obj,
        IEnumerable<string> requiredKeys,
        string path,
        IEnumerable<string>? optionalKeys = null)
    {
        Assert.Equal(JsonValueKind.Object, obj.ValueKind);

        var actual = obj.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        var required = requiredKeys.ToHashSet(StringComparer.Ordinal);
        var allowed = new HashSet<string>(required, StringComparer.Ordinal);
        if (optionalKeys is not null)
        {
            foreach (var opt in optionalKeys)
                allowed.Add(opt);
        }

        foreach (var req in required)
            Assert.True(actual.Contains(req), $"Missing required key '{req}' at {path}.");

        foreach (var key in actual)
            Assert.True(allowed.Contains(key), $"Unexpected key '{key}' at {path}.");
    }

    private static void AssertIsoTimestamp(JsonElement el, string path)
    {
        Assert.Equal(JsonValueKind.String, el.ValueKind);
        var raw = el.GetString();
        Assert.False(string.IsNullOrWhiteSpace(raw), $"Empty timestamp at {path}.");
        Assert.True(
            DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _),
            $"Invalid ISO 8601 timestamp '{raw}' at {path}.");
    }

    private static void AssertBool(JsonElement el) =>
        Assert.True(el.ValueKind is JsonValueKind.True or JsonValueKind.False);

    private static void AssertBoolOrNull(JsonElement el) =>
        Assert.True(el.ValueKind is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null);

    private static void AssertIntOrNull(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.Null)
            return;

        Assert.Equal(JsonValueKind.Number, el.ValueKind);
        Assert.True(el.TryGetInt32(out _));
    }

    private static void AssertStringOrNull(JsonElement el) =>
        Assert.True(el.ValueKind is JsonValueKind.String or JsonValueKind.Null);

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SecureCheck.sln")))
            dir = dir.Parent;

        return dir?.FullName ?? throw new InvalidOperationException("Could not find SecureCheck.sln above the test output folder.");
    }
}
