using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;
using ComputerCreateModel = SecureCheck.Web.Pages.Computers.CreateModel;
using ComputerEditModel = SecureCheck.Web.Pages.Computers.EditModel;
using DiagnosticsIndexModel = SecureCheck.Web.Pages.Admin.Diagnostics.IndexModel;

namespace SecureCheck.Tests;

public class PowerShellRunnerTests
{
    // ---------- 1. Host Mode Routing ----------

    [Theory]
    [InlineData("localhost")]
    [InlineData("LOCALHOST")]
    [InlineData("  localhost  ")]
    [InlineData("127.0.0.1")]
    [InlineData(".")]
    public void DetermineMode_routes_local_identifiers_to_Local_mode(string hostName)
    {
        Assert.Equal(ExecutionMode.Local, PowerShellRunner.DetermineMode(hostName));
        Assert.True(PowerShellRunner.IsLocalHost(hostName));
    }

    [Fact]
    public void DetermineMode_routes_current_Environment_MachineName_case_insensitively_to_Local_mode()
    {
        var machineName = Environment.MachineName;

        Assert.Equal(ExecutionMode.Local, PowerShellRunner.DetermineMode(machineName));
        Assert.Equal(ExecutionMode.Local, PowerShellRunner.DetermineMode(machineName.ToLowerInvariant()));
        Assert.Equal(ExecutionMode.Local, PowerShellRunner.DetermineMode($"  {machineName.ToUpperInvariant()}  "));
    }

    [Theory]
    [InlineData("demo:weak", "weak-pc.json", "SC-LAB-01")]
    [InlineData("DEMO:WEAK", "weak-pc.json", "SC-LAB-01")]
    [InlineData("  demo:secure  ", "secure-pc.json", "SC-LAB-02")]
    [InlineData("demo:error", "partial-error.json", "SC-LAB-02")]
    public void DetermineMode_and_TryGetDemoEndpoint_route_builtin_demo_endpoints(
        string hostName,
        string expectedFixture,
        string expectedComputerName)
    {
        Assert.Equal(ExecutionMode.Demo, PowerShellRunner.DetermineMode(hostName));
        Assert.True(PowerShellRunner.TryGetDemoEndpoint(hostName, out var fixture, out var simulatedName));
        Assert.Equal(expectedFixture, fixture);
        Assert.Equal(expectedComputerName, simulatedName);
    }

    [Theory]
    [InlineData("192.168.56.101")]
    [InlineData("192.168.99.99")]
    [InlineData("SC-LAB-01")]
    [InlineData("pc01.campus.edu")]
    public void DetermineMode_routes_other_hosts_and_IPs_to_Remote_mode(string hostName)
    {
        Assert.Equal(ExecutionMode.Remote, PowerShellRunner.DetermineMode(hostName));
        Assert.False(PowerShellRunner.IsLocalHost(hostName));
        Assert.False(PowerShellRunner.TryGetDemoEndpoint(hostName, out _, out _));
    }

    [Fact]
    public async Task Unknown_demo_endpoint_fails_cleanly_without_attempting_WinRM()
    {
        var runner = new PowerShellRunner();

        var testRes = await runner.RunTestAsync("demo:nonexistent", null, null, timeoutSeconds: 5);
        Assert.False(testRes.Success);
        Assert.Equal(RunnerErrorKind.Other, testRes.ErrorKind);
        Assert.Contains("Unknown demo endpoint", testRes.ErrorMessage, StringComparison.OrdinalIgnoreCase);

        var auditRes = await runner.RunAuditAsync("demo:nonexistent", null, null, timeoutSeconds: 5);
        Assert.False(auditRes.Success);
        Assert.Equal(RunnerErrorKind.Other, auditRes.ErrorKind);
        Assert.Contains("Unknown demo endpoint", auditRes.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- 2. Credential Resolution & Fallback ----------

    [Theory]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("demo:weak")]
    [InlineData("demo:secure")]
    public void ResolveCredentials_skips_credentials_for_Local_and_Demo_modes(string hostName)
    {
        var runner = new PowerShellRunner();
        var computer = new Computer { Name = "Test", HostName = hostName };
        var emptySettings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var resolution = runner.ResolveCredentials(computer, emptySettings);

        Assert.True(resolution.Success);
        Assert.False(resolution.RequiresCredentials);
        Assert.Null(resolution.UserName);
        Assert.Null(resolution.Password);
    }

    [Fact]
    public void ResolveCredentials_prefers_per_computer_credential_over_default_AppSettings()
    {
        using var dp = new TempProtectorScope();
        var runner = new PowerShellRunner(dp.Protector);

        var computer = new Computer
        {
            Name = "SC-LAB-01",
            HostName = "192.168.56.101",
            CredentialUserName = @"SC-LAB-01\customadmin",
            CredentialPasswordProtected = dp.Protector.Protect("CustomPass#123")
        };

        var settings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [AppSettingKeys.DefaultCredentialUserName] = @".\defaultadmin",
            [AppSettingKeys.DefaultCredentialPasswordProtected] = dp.Protector.Protect("DefaultPass#456")
        };

        var resolution = runner.ResolveCredentials(computer, settings);

        Assert.True(resolution.Success);
        Assert.True(resolution.RequiresCredentials);
        Assert.Equal(@"SC-LAB-01\customadmin", resolution.UserName);
        Assert.Equal("CustomPass#123", resolution.Password);
    }

    [Fact]
    public void ResolveCredentials_falls_back_to_default_AppSettings_when_computer_has_no_custom_credential()
    {
        using var dp = new TempProtectorScope();
        var runner = new PowerShellRunner(dp.Protector);

        var computer = new Computer
        {
            Name = "SC-LAB-02",
            HostName = "192.168.56.102",
            CredentialUserName = null,
            CredentialPasswordProtected = null
        };

        var settings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [AppSettingKeys.DefaultCredentialUserName] = @"CAMPUS\scaudit",
            [AppSettingKeys.DefaultCredentialPasswordProtected] = dp.Protector.Protect("FallbackSecret!99")
        };

        var resolution = runner.ResolveCredentials(computer, settings);

        Assert.True(resolution.Success);
        Assert.True(resolution.RequiresCredentials);
        Assert.Equal(@"CAMPUS\scaudit", resolution.UserName);
        Assert.Equal("FallbackSecret!99", resolution.Password);
    }

    [Fact]
    public async Task Remote_mode_returns_clear_missing_credential_message_when_neither_custom_nor_default_exists()
    {
        using var dp = new TempProtectorScope();
        var runner = new PowerShellRunner(dp.Protector);

        var computer = new Computer
        {
            Name = "SC-REMOTE-01",
            HostName = "192.168.99.99"
        };
        var emptySettings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var resolution = runner.ResolveCredentials(computer, emptySettings);
        Assert.False(resolution.Success);
        Assert.Equal(PowerShellRunner.MissingCredentialMessage, resolution.ErrorMessage);

        var auditRes = await runner.RunAuditAsync(computer);
        Assert.False(auditRes.Success);
        Assert.Equal(RunnerErrorKind.Other, auditRes.ErrorKind);
        Assert.Equal("No audit credential set — add one in Settings.", auditRes.ErrorMessage);

        var testRes = await runner.RunTestAsync(computer);
        Assert.False(testRes.Success);
        Assert.Equal(RunnerErrorKind.Other, testRes.ErrorKind);
        Assert.Equal("No audit credential set — add one in Settings.", testRes.ErrorMessage);
    }

    [Fact]
    public void ResolveCredentials_handles_corrupted_ciphertext_gracefully_without_exposing_ciphertext()
    {
        using var dp = new TempProtectorScope();
        var runner = new PowerShellRunner(dp.Protector);
        const string corruptedPayload = "TAMPERED_CIPHERTEXT_PAYLOAD_XYZ";

        var computer = new Computer
        {
            Name = "SC-CORRUPT",
            HostName = "192.168.56.150",
            CredentialUserName = "scaudit",
            CredentialPasswordProtected = corruptedPayload
        };

        var resolution = runner.ResolveCredentials(computer, new Dictionary<string, string>());

        Assert.False(resolution.Success);
        Assert.NotNull(resolution.ErrorMessage);
        Assert.DoesNotContain(corruptedPayload, resolution.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- 3. Error Mapping & Password Scrubbing ----------

    [Theory]
    [InlineData("Connecting to remote server 192.168.56.101 failed with the following error message : Access is denied.")]
    [InlineData("Logon failure: unknown user name or bad password.")]
    public void MapError_maps_authentication_and_authorization_failures_to_AccessDenied(string rawError)
    {
        var (kind, message) = PowerShellRunner.MapError(rawError);

        Assert.Equal(RunnerErrorKind.AccessDenied, kind);
        Assert.Equal("Login failed or the account is not an administrator on this computer.", message);
    }

    [Theory]
    [InlineData("WinRM cannot complete the operation. Verify that the specified computer name is valid.")]
    [InlineData("The client cannot connect to the destination specified in the request.")]
    [InlineData("The WinRM client cannot process the request because the server name cannot be resolved.")]
    public void MapError_maps_network_and_WinRM_reachability_errors_to_Unreachable(string rawError)
    {
        var (kind, message) = PowerShellRunner.MapError(rawError);

        Assert.Equal(RunnerErrorKind.Unreachable, kind);
        Assert.Equal("Computer is off, not on the network, or remote PowerShell is not turned on.", message);
    }

    [Fact]
    public void MapError_maps_TrustedHosts_before_generic_WinRM_text_to_NotTrusted()
    {
        const string rawError =
            "Connecting to remote server 192.168.56.101 failed with the following error message : " +
            "The WinRM client cannot process the request. Cannot connect unless HTTPS transport is used " +
            "or the destination machine is added to the TrustedHosts configuration setting.";

        var (kind, message) = PowerShellRunner.MapError(rawError);

        Assert.Equal(RunnerErrorKind.NotTrusted, kind);
        Assert.Equal("This computer is not in the TrustedHosts list (workgroup networks only).", message);
    }

    [Fact]
    public void MapError_maps_timeout_messages_to_Timeout()
    {
        var (kind, message) = PowerShellRunner.MapError("The operation timed out waiting for response.");

        Assert.Equal(RunnerErrorKind.Timeout, kind);
        Assert.Contains("timed out", message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MapError_maps_unexpected_errors_to_Other_and_redacts_any_password_occurrence()
    {
        const string secret = "Super$ecretAuditPw!2026";
        var raw = $"Unexpected remoting fault while authenticating with {secret} and {secret.ToUpperInvariant()}.";

        var (kind, message) = PowerShellRunner.MapError(raw, secretToRedact: secret);

        Assert.Equal(RunnerErrorKind.Other, kind);
        Assert.DoesNotContain(secret, message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED]", message, StringComparison.Ordinal);
    }

    // ---------- 4. Live Demo Endpoint Execution (Mode B) ----------

    [Theory]
    [InlineData("demo:weak", "SC-LAB-01")]
    [InlineData("demo:secure", "SC-LAB-02")]
    [InlineData("demo:error", "SC-LAB-02")]
    public async Task RunTestAsync_for_demo_endpoints_succeeds_without_credentials(
        string demoHost,
        string expectedComputerName)
    {
        var runner = new PowerShellRunner();

        var result = await runner.RunTestAsync(demoHost, userName: null, password: null, timeoutSeconds: 10);

        Assert.True(result.Success, result.ErrorMessage);
        Assert.Null(result.ErrorKind);
        Assert.Equal(expectedComputerName, result.ComputerName);
        Assert.Equal("5.1 (Simulated Endpoint)", result.PowerShellVersion);
    }

    [Theory]
    [InlineData("demo:weak", "weak-pc.json", "SC-LAB-01")]
    [InlineData("demo:secure", "secure-pc.json", "SC-LAB-02")]
    [InlineData("demo:error", "partial-error.json", "SC-LAB-02")]
    public async Task RunAuditAsync_for_demo_endpoints_simulates_delay_and_returns_fixture_json(
        string demoHost,
        string expectedFixtureFile,
        string expectedComputerName)
    {
        var runner = new PowerShellRunner();
        var expectedJson = (await File.ReadAllTextAsync(
            Path.Combine(AppContext.BaseDirectory, "Scripts", "Fixtures", expectedFixtureFile))).Trim();

        var result = await runner.RunAuditAsync(demoHost, userName: null, password: null, timeoutSeconds: 15);

        Assert.True(result.Success, result.ErrorMessage);
        Assert.Null(result.ErrorKind);
        Assert.NotNull(result.Json);
        Assert.True(result.Duration.TotalMilliseconds >= 900, $"Expected >= 1s simulated delay, actual {result.Duration.TotalMilliseconds:F0}ms.");
        Assert.Equal(expectedJson, result.Json!.Trim(), ignoreLineEndingDifferences: true);

        using var doc = JsonDocument.Parse(result.Json);
        Assert.Equal(1, doc.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(expectedComputerName, doc.RootElement.GetProperty("computerName").GetString());
    }

    // ---------- 5. Live Local Machine Execution (Mode A) ----------

    [Fact]
    public async Task RunTestAsync_on_localhost_succeeds_without_credentials_and_returns_local_machine_info()
    {
        var runner = new PowerShellRunner();

        var result = await runner.RunTestAsync("localhost", userName: null, password: null, timeoutSeconds: 20);

        Assert.True(result.Success, result.ErrorMessage);
        Assert.Null(result.ErrorKind);
        Assert.Equal(Environment.MachineName, result.ComputerName);
        Assert.False(string.IsNullOrWhiteSpace(result.PowerShellVersion));
        Assert.StartsWith("5.1", result.PowerShellVersion);
    }

    [Fact]
    public async Task RunAuditAsync_on_localhost_runs_audit_script_directly_without_WinRM_or_credentials()
    {
        var runner = new PowerShellRunner();

        var result = await runner.RunAuditAsync("localhost", userName: null, password: null, timeoutSeconds: 30);

        Assert.True(result.Success, result.ErrorMessage);
        Assert.Null(result.ErrorKind);
        Assert.False(string.IsNullOrWhiteSpace(result.Json));

        using var doc = JsonDocument.Parse(result.Json!);
        var root = doc.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(Environment.MachineName, root.GetProperty("computerName").GetString(), ignoreCase: true);

        // Verify Diagnostics pretty-printer produces indented multi-line JSON.
        var pretty = DiagnosticsIndexModel.FormatJsonPretty(result.Json!);
        Assert.Contains("\n", pretty);
        Assert.Contains("\"schemaVersion\": 1", pretty);
    }

    [Fact]
    public async Task Timeout_enforcement_returns_Timeout_error_kind_when_execution_exceeds_timeoutSeconds()
    {
        var runner = new PowerShellRunner(fixedDemoDelayMs: 3000);

        var result = await runner.RunAuditAsync("demo:weak", userName: null, password: null, timeoutSeconds: 1);

        Assert.False(result.Success);
        Assert.Equal(RunnerErrorKind.Timeout, result.ErrorKind);
        Assert.Contains("timed out", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Caller_CancellationToken_cancels_running_audit()
    {
        var runner = new PowerShellRunner();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            runner.RunAuditAsync("demo:weak", userName: null, password: null, timeoutSeconds: 30, ct: cts.Token));
    }

    [Fact]
    public async Task Mode_C_PowerShell_SDK_Invoke_Command_executes_parameterized_and_maps_WinRM_failure_without_exposing_password()
    {
        var runner = new PowerShellRunner();
        const string secretPassword = "UnitTest$ecretPassword!42";

        var result = await runner.RunTestAsync(
            "nonexistent-host-94f6bf03.invalid",
            userName: @"CAMPUS\scaudit",
            password: secretPassword,
            timeoutSeconds: 10);

        Assert.False(result.Success);
        // On a workgroup PC without '*' in TrustedHosts, WSMan rejects before DNS with NotTrusted;
        // on a domain PC or with '*' in TrustedHosts, WSMan fails DNS/connect with Unreachable.
        Assert.Contains(result.ErrorKind, new RunnerErrorKind?[] { RunnerErrorKind.NotTrusted, RunnerErrorKind.Unreachable });
        var expectedFriendly = result.ErrorKind == RunnerErrorKind.NotTrusted
            ? PowerShellRunner.NotTrustedFriendlyMessage
            : PowerShellRunner.UnreachableFriendlyMessage;
        Assert.Equal(expectedFriendly, result.ErrorMessage);
        Assert.DoesNotContain(secretPassword, result.ErrorMessage ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- 6. Computer HostName Form Validation ----------

    [Theory]
    [InlineData("localhost", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData(".", true)]
    [InlineData("192.168.99.99", true)]
    [InlineData("SC-LAB-01.campus.edu", true)]
    [InlineData("demo:weak", true)]
    [InlineData("demo:secure", true)]
    [InlineData("demo:error", true)]
    [InlineData("DEMO:WEAK", true)]
    [InlineData("demo:invalid", false)]
    [InlineData("192.168.1.1; whoami", false)]
    [InlineData("host with spaces", false)]
    [InlineData("http://localhost", false)]
    public void Computer_Create_and_Edit_HostName_validation_allows_valid_hosts_and_builtin_demos_only(
        string hostName,
        bool expectedValid)
    {
        var createInput = new ComputerCreateModel.InputModel
        {
            Name = "Test-PC",
            HostName = hostName
        };
        var createResults = new List<ValidationResult>();
        var isCreateValid = Validator.TryValidateObject(
            createInput,
            new ValidationContext(createInput),
            createResults,
            validateAllProperties: true);

        Assert.Equal(expectedValid, isCreateValid);

        var editInput = new ComputerEditModel.InputModel
        {
            Id = 1,
            Name = "Test-PC",
            HostName = hostName
        };
        var editResults = new List<ValidationResult>();
        var isEditValid = Validator.TryValidateObject(
            editInput,
            new ValidationContext(editInput),
            editResults,
            validateAllProperties: true);

        Assert.Equal(expectedValid, isEditValid);
    }

    private sealed class TempProtectorScope : IDisposable
    {
        private readonly DirectoryInfo _tempDir;
        public CredentialProtector Protector { get; }

        public TempProtectorScope()
        {
            _tempDir = Directory.CreateDirectory(
                Path.Combine(Path.GetTempPath(), "SecureCheckRunnerTests_" + Guid.NewGuid().ToString("N")));
            var provider = DataProtectionProvider.Create(_tempDir, cfg => cfg.SetApplicationName("SecureCheck"));
            Protector = new CredentialProtector(provider);
        }

        public void Dispose()
        {
            try
            {
                _tempDir.Delete(recursive: true);
            }
            catch
            {
                // Ignore temp cleanup locks.
            }
        }
    }
}
