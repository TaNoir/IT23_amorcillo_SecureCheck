using System.Diagnostics;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Security;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>
/// Categorizes PowerShell connection or script failures for UI alerts and audit status handling.
/// </summary>
public enum RunnerErrorKind
{
    AccessDenied,
    Unreachable,
    NotTrusted,
    Timeout,
    Other
}

/// <summary>
/// Execution target mode selected from a computer's HostName.
/// </summary>
public enum ExecutionMode
{
    Local,
    Demo,
    Remote
}

/// <summary>
/// Result of running Invoke-SecureCheckAudit.ps1 against a target computer.
/// </summary>
public sealed class RunnerResult
{
    public bool Success { get; init; }
    public string? Json { get; init; }
    public string? ErrorMessage { get; init; }
    public RunnerErrorKind? ErrorKind { get; init; }
    public TimeSpan Duration { get; init; }

    public static RunnerResult Ok(string json, TimeSpan duration) => new()
    {
        Success = true,
        Json = json,
        Duration = duration
    };

    public static RunnerResult Fail(RunnerErrorKind kind, string message, TimeSpan duration) => new()
    {
        Success = false,
        ErrorKind = kind,
        ErrorMessage = message,
        Duration = duration
    };
}

/// <summary>
/// Result of testing connectivity to a target computer.
/// </summary>
public sealed class TestConnectionResult
{
    public bool Success { get; init; }
    public string? ComputerName { get; init; }
    public string? PowerShellVersion { get; init; }
    public string? ErrorMessage { get; init; }
    public RunnerErrorKind? ErrorKind { get; init; }
    public TimeSpan Duration { get; init; }

    public static TestConnectionResult Ok(string computerName, string powerShellVersion, TimeSpan duration) => new()
    {
        Success = true,
        ComputerName = computerName,
        PowerShellVersion = powerShellVersion,
        Duration = duration
    };

    public static TestConnectionResult Fail(RunnerErrorKind kind, string message, TimeSpan duration) => new()
    {
        Success = false,
        ErrorKind = kind,
        ErrorMessage = message,
        Duration = duration
    };
}

/// <summary>
/// Internal result of resolving per-computer or default encrypted credentials.
/// Plain-text password stays in memory only for the duration of the WinRM call.
/// </summary>
internal sealed class CredentialResolution
{
    public bool Success { get; init; }
    public bool RequiresCredentials { get; init; }
    public string? UserName { get; init; }
    public string? Password { get; init; }
    public string? ErrorMessage { get; init; }

    public static CredentialResolution NotRequired() => new()
    {
        Success = true,
        RequiresCredentials = false
    };

    public static CredentialResolution Resolved(string userName, string password) => new()
    {
        Success = true,
        RequiresCredentials = true,
        UserName = userName,
        Password = password
    };

    public static CredentialResolution Failed(string errorMessage) => new()
    {
        Success = false,
        RequiresCredentials = true,
        ErrorMessage = errorMessage
    };
}

/// <summary>
/// Executes the read-only PowerShell audit script and connection checks across:
/// Mode A (local laptop without WinRM/credentials), Mode B (built-in demo fixtures),
/// and Mode C (remote Windows PCs via parameterized PowerShell Remoting / WinRM).
/// Never logs or exposes plain or encrypted passwords.
/// </summary>
public sealed class PowerShellRunner
{
    public const int DefaultAuditTimeoutSeconds = 180;
    public const int DefaultTestTimeoutSeconds = 20;

    public const string HostNameValidationPattern =
        @"^([A-Za-z0-9.-]+|[Dd][Ee][Mm][Oo]:([Ww][Ee][Aa][Kk]|[Ss][Ee][Cc][Uu][Rr][Ee]|[Ee][Rr][Rr][Oo][Rr]))$";

    public const string HostNameValidationMessage =
        "Enter a valid host name or IP address (letters, digits, dots, hyphens), or demo:weak, demo:secure, demo:error.";

    public const string MissingCredentialMessage =
        "No audit credential set — add one in Settings.";

    public const string AccessDeniedFriendlyMessage =
        "Login failed or the account is not an administrator on this computer.";

    public const string UnreachableFriendlyMessage =
        "Computer is off, not on the network, or remote PowerShell is not turned on.";

    public const string NotTrustedFriendlyMessage =
        "This computer is not in the TrustedHosts list (workgroup networks only).";

    public const string SimulatedPowerShellVersion = "5.1 (Simulated Endpoint)";

    private const string RemoteTestScript = "$env:COMPUTERNAME; $PSVersionTable.PSVersion.ToString()";

    private static readonly Regex RemoteHostNameRegex =
        new(@"^[A-Za-z0-9.-]+$", RegexOptions.Compiled);

    private static readonly Regex WhitespaceRegex =
        new(@"\s+", RegexOptions.Compiled);

    private readonly CredentialProtector? _protector;
    private readonly IServiceScopeFactory? _scopeFactory;
    private readonly ILogger<PowerShellRunner> _logger;
    private readonly string _baseDirectory;
    private readonly string _scriptPath;
    private readonly Lazy<string> _lazyScriptText;
    private readonly int? _fixedDemoDelayMs;

    public PowerShellRunner(
        CredentialProtector protector,
        IServiceScopeFactory scopeFactory,
        ILogger<PowerShellRunner> logger)
        : this(protector, scopeFactory, logger, AppContext.BaseDirectory)
    {
    }

    internal PowerShellRunner(
        CredentialProtector? protector = null,
        IServiceScopeFactory? scopeFactory = null,
        ILogger<PowerShellRunner>? logger = null,
        string? baseDirectory = null,
        int? fixedDemoDelayMs = null)
    {
        _protector = protector;
        _scopeFactory = scopeFactory;
        _logger = logger ?? NullLogger<PowerShellRunner>.Instance;
        _baseDirectory = string.IsNullOrWhiteSpace(baseDirectory) ? AppContext.BaseDirectory : baseDirectory;
        _scriptPath = Path.Combine(_baseDirectory, "Scripts", "Invoke-SecureCheckAudit.ps1");
        _lazyScriptText = new Lazy<string>(LoadAuditScriptOnce, LazyThreadSafetyMode.ExecutionAndPublication);
        _fixedDemoDelayMs = fixedDemoDelayMs;
    }

    /// <summary>
    /// Classifies a hostName (trimmed, case-insensitive) into Local, Demo, or Remote execution mode.
    /// </summary>
    public static ExecutionMode DetermineMode(string? hostName)
    {
        if (string.IsNullOrWhiteSpace(hostName))
            return ExecutionMode.Remote;

        var trimmed = hostName.Trim();
        if (IsLocalHost(trimmed))
            return ExecutionMode.Local;

        if (trimmed.StartsWith("demo:", StringComparison.OrdinalIgnoreCase))
            return ExecutionMode.Demo;

        return ExecutionMode.Remote;
    }

    /// <summary>
    /// Returns true for localhost, 127.0.0.1, ., or the current Windows machine name.
    /// </summary>
    public static bool IsLocalHost(string? hostName)
    {
        if (string.IsNullOrWhiteSpace(hostName))
            return false;

        var trimmed = hostName.Trim();
        return trimmed.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("127.0.0.1", StringComparison.Ordinal)
            || trimmed.Equals(".", StringComparison.Ordinal)
            || trimmed.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Maps a built-in demo endpoint identifier to its bundled fixture file and simulated computer name.
    /// </summary>
    public static bool TryGetDemoEndpoint(
        string? hostName,
        out string fixtureFileName,
        out string simulatedComputerName)
    {
        fixtureFileName = string.Empty;
        simulatedComputerName = string.Empty;

        if (string.IsNullOrWhiteSpace(hostName))
            return false;

        switch (hostName.Trim().ToLowerInvariant())
        {
            case "demo:weak":
                fixtureFileName = "weak-pc.json";
                simulatedComputerName = "SC-LAB-01";
                return true;
            case "demo:secure":
                fixtureFileName = "secure-pc.json";
                simulatedComputerName = "SC-LAB-02";
                return true;
            case "demo:error":
                fixtureFileName = "partial-error.json";
                simulatedComputerName = "SC-LAB-02";
                return true;
            default:
                return false;
        }
    }

    /// <summary>
    /// Resolves credentials and timeout from the database for a Computer entity and runs the audit script.
    /// </summary>
    public async Task<RunnerResult> RunAuditAsync(Computer computer, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(computer);

        var mode = DetermineMode(computer.HostName);
        var settings = await LoadSettingsMapAsync(ct);
        var timeoutSeconds = GetAuditTimeoutSeconds(settings);

        if (mode is ExecutionMode.Local or ExecutionMode.Demo)
        {
            return await RunAuditAsync(computer.HostName, userName: null, password: null, timeoutSeconds, ct);
        }

        var cred = ResolveCredentials(computer, settings);
        if (!cred.Success)
        {
            return RunnerResult.Fail(RunnerErrorKind.Other, cred.ErrorMessage ?? MissingCredentialMessage, TimeSpan.Zero);
        }

        return await RunAuditAsync(computer.HostName, cred.UserName, cred.Password, timeoutSeconds, ct);
    }

    /// <summary>
    /// Resolves credentials from the database for a Computer entity and runs a lightweight connection test.
    /// </summary>
    public async Task<TestConnectionResult> RunTestAsync(
        Computer computer,
        int timeoutSeconds = DefaultTestTimeoutSeconds,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(computer);

        var mode = DetermineMode(computer.HostName);
        if (mode is ExecutionMode.Local or ExecutionMode.Demo)
        {
            return await RunTestAsync(computer.HostName, userName: null, password: null, timeoutSeconds, ct);
        }

        var settings = await LoadSettingsMapAsync(ct);
        var cred = ResolveCredentials(computer, settings);
        if (!cred.Success)
        {
            return TestConnectionResult.Fail(RunnerErrorKind.Other, cred.ErrorMessage ?? MissingCredentialMessage, TimeSpan.Zero);
        }

        return await RunTestAsync(computer.HostName, cred.UserName, cred.Password, timeoutSeconds, ct);
    }

    /// <summary>
    /// Runs Invoke-SecureCheckAudit.ps1 in Mode A (local), Mode B (demo fixture), or Mode C (remote WinRM).
    /// </summary>
    public async Task<RunnerResult> RunAuditAsync(
        string hostName,
        string? userName,
        string? password,
        int timeoutSeconds = DefaultAuditTimeoutSeconds,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(hostName))
        {
            return RunnerResult.Fail(RunnerErrorKind.Other, "Host name is required.", sw.Elapsed);
        }

        var trimmedHost = hostName.Trim();
        var effectiveTimeout = timeoutSeconds > 0 ? timeoutSeconds : DefaultAuditTimeoutSeconds;
        var mode = DetermineMode(trimmedHost);

        return mode switch
        {
            ExecutionMode.Local => await RunAuditLocalAsync(effectiveTimeout, sw, ct),
            ExecutionMode.Demo => await RunAuditDemoAsync(trimmedHost, effectiveTimeout, sw, ct),
            _ => await RunAuditRemoteAsync(trimmedHost, userName, password, effectiveTimeout, sw, ct)
        };
    }

    /// <summary>
    /// Tests connectivity to a target host in Mode A (local), Mode B (demo), or Mode C (remote WinRM).
    /// </summary>
    public async Task<TestConnectionResult> RunTestAsync(
        string hostName,
        string? userName,
        string? password,
        int timeoutSeconds = DefaultTestTimeoutSeconds,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        if (string.IsNullOrWhiteSpace(hostName))
        {
            return TestConnectionResult.Fail(RunnerErrorKind.Other, "Host name is required.", sw.Elapsed);
        }

        var trimmedHost = hostName.Trim();
        var effectiveTimeout = timeoutSeconds > 0 ? timeoutSeconds : DefaultTestTimeoutSeconds;
        var mode = DetermineMode(trimmedHost);

        return mode switch
        {
            ExecutionMode.Local => await RunTestLocalAsync(effectiveTimeout, sw, ct),
            ExecutionMode.Demo => await RunTestDemoAsync(trimmedHost, effectiveTimeout, sw, ct),
            _ => await RunTestRemoteAsync(trimmedHost, userName, password, effectiveTimeout, sw, ct)
        };
    }

    /// <summary>
    /// Resolves per-computer encrypted credentials, falling back to default AppSettings credentials.
    /// Local and Demo endpoints bypass credentials completely.
    /// </summary>
    internal CredentialResolution ResolveCredentials(
        Computer computer,
        IReadOnlyDictionary<string, string> appSettings)
    {
        ArgumentNullException.ThrowIfNull(computer);
        ArgumentNullException.ThrowIfNull(appSettings);

        if (DetermineMode(computer.HostName) is ExecutionMode.Local or ExecutionMode.Demo)
        {
            return CredentialResolution.NotRequired();
        }

        if (_protector is null)
        {
            return CredentialResolution.Failed("Credential encryption service is not configured.");
        }

        if (!string.IsNullOrWhiteSpace(computer.CredentialUserName) &&
            !string.IsNullOrEmpty(computer.CredentialPasswordProtected))
        {
            try
            {
                var plain = _protector.Unprotect(computer.CredentialPasswordProtected);
                if (!string.IsNullOrEmpty(plain))
                {
                    return CredentialResolution.Resolved(computer.CredentialUserName.Trim(), plain);
                }
            }
            catch (CryptographicException)
            {
                _logger.LogWarning("Could not decrypt stored custom credential for computer {ComputerName}.", computer.Name);
                return CredentialResolution.Failed(
                    "Saved credential for this computer could not be decrypted. Re-enter the password on Edit Computer.");
            }
        }

        appSettings.TryGetValue(AppSettingKeys.DefaultCredentialUserName, out var defaultUser);
        appSettings.TryGetValue(AppSettingKeys.DefaultCredentialPasswordProtected, out var defaultProtectedPass);

        if (!string.IsNullOrWhiteSpace(defaultUser) && !string.IsNullOrEmpty(defaultProtectedPass))
        {
            try
            {
                var plain = _protector.Unprotect(defaultProtectedPass);
                if (!string.IsNullOrEmpty(plain))
                {
                    return CredentialResolution.Resolved(defaultUser.Trim(), plain);
                }
            }
            catch (CryptographicException)
            {
                _logger.LogWarning("Could not decrypt stored default audit credential from AppSettings.");
                return CredentialResolution.Failed(
                    "Saved default audit credential could not be decrypted. Re-enter the password in Admin > Settings.");
            }
        }

        return CredentialResolution.Failed(MissingCredentialMessage);
    }

    /// <summary>
    /// Maps PowerShell / WinRM exception messages to user-friendly ErrorKind + ErrorMessage pairs,
    /// scrubbing any occurrence of a password if present.
    /// </summary>
    public static (RunnerErrorKind Kind, string Message) MapError(
        string? rawMessage,
        string? secretToRedact = null)
    {
        var sanitized = SanitizeErrorMessage(rawMessage, secretToRedact);
        if (string.IsNullOrWhiteSpace(sanitized))
        {
            return (RunnerErrorKind.Other, "An unknown PowerShell execution error occurred.");
        }

        // Check TrustedHosts before generic WinRM text because WinRM's TrustedHosts error mentions both.
        if (sanitized.Contains("TrustedHosts", StringComparison.OrdinalIgnoreCase))
        {
            return (RunnerErrorKind.NotTrusted, NotTrustedFriendlyMessage);
        }

        if (sanitized.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("Logon failure", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("unknown user name or bad password", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("credentials supplied to the package were not recognized", StringComparison.OrdinalIgnoreCase))
        {
            return (RunnerErrorKind.AccessDenied, AccessDeniedFriendlyMessage);
        }

        if (sanitized.Contains("WinRM cannot complete the operation", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("cannot connect", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("server name cannot be resolved", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("network path was not found", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("No such host is known", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("connection attempt failed", StringComparison.OrdinalIgnoreCase))
        {
            return (RunnerErrorKind.Unreachable, UnreachableFriendlyMessage);
        }

        if (sanitized.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
            sanitized.Contains("operation timeout", StringComparison.OrdinalIgnoreCase))
        {
            return (RunnerErrorKind.Timeout, "Connection timed out before the computer responded.");
        }

        return (RunnerErrorKind.Other, sanitized);
    }

    internal static string SanitizeErrorMessage(string? rawMessage, string? secretToRedact)
    {
        if (string.IsNullOrWhiteSpace(rawMessage))
            return string.Empty;

        var cleaned = rawMessage;
        if (!string.IsNullOrEmpty(secretToRedact))
        {
            cleaned = cleaned.Replace(secretToRedact, "[REDACTED]", StringComparison.Ordinal);
            cleaned = cleaned.Replace(secretToRedact, "[REDACTED]", StringComparison.OrdinalIgnoreCase);
        }

        return WhitespaceRegex.Replace(cleaned, " ").Trim();
    }

    // ---------- Mode A: Local Machine ----------

    private async Task<RunnerResult> RunAuditLocalAsync(
        int timeoutSeconds,
        Stopwatch sw,
        CancellationToken ct)
    {
        try
        {
            // Verify and cache script text once from AppContext.BaseDirectory.
            _ = _lazyScriptText.Value;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load audit script from {ScriptPath}.", _scriptPath);
            return RunnerResult.Fail(RunnerErrorKind.Other, "Audit script file could not be loaded from the server output folder.", sw.Elapsed);
        }

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        var psi = CreateLocalPowerShellStartInfo();
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(_scriptPath);

        using var process = new Process { StartInfo = psi };
        try
        {
            if (!process.Start())
            {
                return RunnerResult.Fail(RunnerErrorKind.Other, "Failed to start local Windows PowerShell process.", sw.Elapsed);
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await Task.WhenAll(stdoutTask, stderrTask, process.WaitForExitAsync(linkedCts.Token));

            var json = (await stdoutTask).Trim();
            var stderr = (await stderrTask).Trim();

            if (string.IsNullOrWhiteSpace(json))
            {
                var detail = string.IsNullOrWhiteSpace(stderr)
                    ? $"Local PowerShell exited with code {process.ExitCode} and produced no JSON output."
                    : SanitizeErrorMessage(stderr, secretToRedact: null);
                return RunnerResult.Fail(RunnerErrorKind.Other, detail, sw.Elapsed);
            }

            return RunnerResult.Ok(json, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            KillProcessSafe(process);
            if (ct.IsCancellationRequested && !timeoutCts.IsCancellationRequested)
                throw;

            return RunnerResult.Fail(
                RunnerErrorKind.Timeout,
                $"Local audit script timed out after {timeoutSeconds} seconds.",
                sw.Elapsed);
        }
        catch (Exception ex)
        {
            KillProcessSafe(process);
            var (kind, message) = MapError(ex.Message);
            return RunnerResult.Fail(kind, message, sw.Elapsed);
        }
    }

    private static async Task<TestConnectionResult> RunTestLocalAsync(
        int timeoutSeconds,
        Stopwatch sw,
        CancellationToken ct)
    {
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        var psi = CreateLocalPowerShellStartInfo();
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add("$PSVersionTable.PSVersion.ToString()");

        using var process = new Process { StartInfo = psi };
        try
        {
            if (!process.Start())
            {
                return TestConnectionResult.Fail(RunnerErrorKind.Other, "Failed to start local Windows PowerShell process.", sw.Elapsed);
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await Task.WhenAll(stdoutTask, stderrTask, process.WaitForExitAsync(linkedCts.Token));

            var version = (await stdoutTask).Trim();
            var stderr = (await stderrTask).Trim();

            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(version))
            {
                var detail = string.IsNullOrWhiteSpace(stderr)
                    ? "Could not query local Windows PowerShell version."
                    : SanitizeErrorMessage(stderr, secretToRedact: null);
                return TestConnectionResult.Fail(RunnerErrorKind.Other, detail, sw.Elapsed);
            }

            return TestConnectionResult.Ok(Environment.MachineName, version, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            KillProcessSafe(process);
            if (ct.IsCancellationRequested && !timeoutCts.IsCancellationRequested)
                throw;

            return TestConnectionResult.Fail(
                RunnerErrorKind.Timeout,
                $"Local connection check timed out after {timeoutSeconds} seconds.",
                sw.Elapsed);
        }
        catch (Exception ex)
        {
            KillProcessSafe(process);
            var (kind, message) = MapError(ex.Message);
            return TestConnectionResult.Fail(kind, message, sw.Elapsed);
        }
    }

    private static ProcessStartInfo CreateLocalPowerShellStartInfo()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        return psi;
    }

    private static void KillProcessSafe(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Ignore cleanup errors if the process already exited.
        }
    }

    // ---------- Mode B: Built-in Demo Endpoints ----------

    private async Task<RunnerResult> RunAuditDemoAsync(
        string trimmedHost,
        int timeoutSeconds,
        Stopwatch sw,
        CancellationToken ct)
    {
        if (!TryGetDemoEndpoint(trimmedHost, out var fixtureFileName, out _))
        {
            return RunnerResult.Fail(
                RunnerErrorKind.Other,
                $"Unknown demo endpoint '{trimmedHost}'. Use demo:weak, demo:secure, or demo:error.",
                sw.Elapsed);
        }

        var fixturePath = Path.Combine(_baseDirectory, "Scripts", "Fixtures", fixtureFileName);
        if (!File.Exists(fixturePath))
        {
            return RunnerResult.Fail(
                RunnerErrorKind.Other,
                $"Demo fixture '{fixtureFileName}' was not found in output Scripts/Fixtures.",
                sw.Elapsed);
        }

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            // Simulate realistic 1-2 second remote scan latency.
            var simulatedDelayMs = _fixedDemoDelayMs ?? Random.Shared.Next(1000, 1801);
            await Task.Delay(simulatedDelayMs, linkedCts.Token);

            var json = await File.ReadAllTextAsync(fixturePath, linkedCts.Token);
            return RunnerResult.Ok(json.Trim(), sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            if (ct.IsCancellationRequested && !timeoutCts.IsCancellationRequested)
                throw;

            return RunnerResult.Fail(
                RunnerErrorKind.Timeout,
                $"Audit timed out after {timeoutSeconds} seconds.",
                sw.Elapsed);
        }
    }

    private async Task<TestConnectionResult> RunTestDemoAsync(
        string trimmedHost,
        int timeoutSeconds,
        Stopwatch sw,
        CancellationToken ct)
    {
        if (!TryGetDemoEndpoint(trimmedHost, out var fixtureFileName, out var simulatedComputerName))
        {
            return TestConnectionResult.Fail(
                RunnerErrorKind.Other,
                $"Unknown demo endpoint '{trimmedHost}'. Use demo:weak, demo:secure, or demo:error.",
                sw.Elapsed);
        }

        var fixturePath = Path.Combine(_baseDirectory, "Scripts", "Fixtures", fixtureFileName);
        if (!File.Exists(fixturePath))
        {
            return TestConnectionResult.Fail(
                RunnerErrorKind.Other,
                $"Demo fixture '{fixtureFileName}' was not found in output Scripts/Fixtures.",
                sw.Elapsed);
        }

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        try
        {
            await Task.Delay(250, linkedCts.Token);
            return TestConnectionResult.Ok(simulatedComputerName, SimulatedPowerShellVersion, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            if (ct.IsCancellationRequested && !timeoutCts.IsCancellationRequested)
                throw;

            return TestConnectionResult.Fail(
                RunnerErrorKind.Timeout,
                $"Connection timed out after {timeoutSeconds} seconds.",
                sw.Elapsed);
        }
    }

    // ---------- Mode C: Remote Network Computer (WinRM via PowerShell SDK) ----------

    private async Task<RunnerResult> RunAuditRemoteAsync(
        string trimmedHost,
        string? userName,
        string? password,
        int timeoutSeconds,
        Stopwatch sw,
        CancellationToken ct)
    {
        if (!RemoteHostNameRegex.IsMatch(trimmedHost))
        {
            return RunnerResult.Fail(RunnerErrorKind.Other, HostNameValidationMessage, sw.Elapsed);
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrEmpty(password))
        {
            return RunnerResult.Fail(RunnerErrorKind.Other, MissingCredentialMessage, sw.Elapsed);
        }

        string scriptText;
        try
        {
            scriptText = _lazyScriptText.Value;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load audit script from {ScriptPath}.", _scriptPath);
            return RunnerResult.Fail(RunnerErrorKind.Other, "Audit script file could not be loaded from the server output folder.", sw.Elapsed);
        }

        var remoteOutcome = await InvokeRemoteScriptAsync(trimmedHost, userName.Trim(), password, scriptText, timeoutSeconds, ct);
        if (!remoteOutcome.Success)
        {
            return RunnerResult.Fail(remoteOutcome.ErrorKind!.Value, remoteOutcome.ErrorMessage!, sw.Elapsed);
        }

        var json = string.Join(
                Environment.NewLine,
                remoteOutcome.Lines.Where(line => !string.IsNullOrWhiteSpace(line)))
            .Trim();

        if (string.IsNullOrWhiteSpace(json))
        {
            return RunnerResult.Fail(RunnerErrorKind.Other, "Remote audit script returned empty output.", sw.Elapsed);
        }

        return RunnerResult.Ok(json, sw.Elapsed);
    }

    private async Task<TestConnectionResult> RunTestRemoteAsync(
        string trimmedHost,
        string? userName,
        string? password,
        int timeoutSeconds,
        Stopwatch sw,
        CancellationToken ct)
    {
        if (!RemoteHostNameRegex.IsMatch(trimmedHost))
        {
            return TestConnectionResult.Fail(RunnerErrorKind.Other, HostNameValidationMessage, sw.Elapsed);
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrEmpty(password))
        {
            return TestConnectionResult.Fail(RunnerErrorKind.Other, MissingCredentialMessage, sw.Elapsed);
        }

        var remoteOutcome = await InvokeRemoteScriptAsync(trimmedHost, userName.Trim(), password, RemoteTestScript, timeoutSeconds, ct);
        if (!remoteOutcome.Success)
        {
            return TestConnectionResult.Fail(remoteOutcome.ErrorKind!.Value, remoteOutcome.ErrorMessage!, sw.Elapsed);
        }

        var computerName = remoteOutcome.Lines.Count > 0 ? remoteOutcome.Lines[0] : trimmedHost;
        var psVersion = remoteOutcome.Lines.Count > 1 ? remoteOutcome.Lines[1] : "Unknown";

        return TestConnectionResult.Ok(computerName, psVersion, sw.Elapsed);
    }

    private static async Task<(bool Success, IReadOnlyList<string> Lines, RunnerErrorKind? ErrorKind, string? ErrorMessage)> InvokeRemoteScriptAsync(
        string trimmedHost,
        string trimmedUserName,
        string password,
        string scriptText,
        int timeoutSeconds,
        CancellationToken ct)
    {
        using var securePassword = new SecureString();
        foreach (var ch in password)
        {
            securePassword.AppendChar(ch);
        }
        securePassword.MakeReadOnly();

        var credential = new PSCredential(trimmedUserName, securePassword);

        // Cap connection-open timeout at 15s so unreachable IPs report "Computer is off..." within ~20s.
        var openTimeoutSeconds = timeoutSeconds >= 20 ? 15 : Math.Max(1, timeoutSeconds);
        var sessionOption = new PSSessionOption
        {
            OpenTimeout = TimeSpan.FromSeconds(openTimeoutSeconds),
            OperationTimeout = TimeSpan.FromSeconds(timeoutSeconds),
            CancelTimeout = TimeSpan.FromSeconds(5),
            NoMachineProfile = true
        };

        using var ps = System.Management.Automation.PowerShell.Create();
        ps.AddCommand("Invoke-Command")
          .AddParameter("ComputerName", trimmedHost)
          .AddParameter("Credential", credential)
          .AddParameter("ScriptBlock", ScriptBlock.Create(scriptText))
          .AddParameter("SessionOption", sessionOption)
          .AddParameter("ErrorAction", ActionPreference.Stop);

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        await using var stopRegistration = linkedCts.Token.Register(() =>
        {
            try
            {
                ps.BeginStop(null, null);
            }
            catch
            {
                // Ignore if pipeline already stopped.
            }
        });

        try
        {
            var results = await ps.InvokeAsync().WaitAsync(linkedCts.Token);

            var lines = results
                .Where(item => item is not null)
                .SelectMany(item => (item.BaseObject?.ToString() ?? item.ToString() ?? string.Empty)
                    .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .ToList();

            if (lines.Count == 0 && ps.Streams.Error.Count > 0)
            {
                var streamErrors = string.Join(
                    " ",
                    ps.Streams.Error.Select(err => err.Exception?.Message ?? err.ToString()));
                var (kind, message) = MapError(streamErrors, password);
                return (false, Array.Empty<string>(), kind, message);
            }

            return (true, lines, null, null);
        }
        catch (Exception ex) when (ex is OperationCanceledException or PipelineStoppedException or TimeoutException)
        {
            if (ct.IsCancellationRequested && !timeoutCts.IsCancellationRequested)
                throw new OperationCanceledException(ct);

            return (false, Array.Empty<string>(), RunnerErrorKind.Timeout, $"Connection timed out after {timeoutSeconds} seconds.");
        }
        catch (Exception ex)
        {
            var combinedMessage = ExtractExceptionMessages(ex);
            var (kind, message) = MapError(combinedMessage, password);
            return (false, Array.Empty<string>(), kind, message);
        }
    }

    private static string ExtractExceptionMessages(Exception ex)
    {
        var parts = new List<string>();
        Exception? current = ex;
        while (current is not null)
        {
            if (!string.IsNullOrWhiteSpace(current.Message))
            {
                parts.Add(current.Message);
            }

            if (current is IContainsErrorRecord containsErrorRecord &&
                containsErrorRecord.ErrorRecord?.ErrorDetails?.Message is { Length: > 0 } detailsMsg)
            {
                parts.Add(detailsMsg);
            }

            current = current.InnerException;
        }

        return string.Join(" ", parts.Distinct(StringComparer.Ordinal));
    }

    private string LoadAuditScriptOnce()
    {
        if (!File.Exists(_scriptPath))
        {
            throw new FileNotFoundException("PowerShell audit script was not found in the output folder.", _scriptPath);
        }

        return File.ReadAllText(_scriptPath);
    }

    private async Task<Dictionary<string, string>> LoadSettingsMapAsync(CancellationToken ct)
    {
        if (_scopeFactory is null)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        return await db.AppSettings
            .AsNoTracking()
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase, ct);
    }

    private static int GetAuditTimeoutSeconds(IReadOnlyDictionary<string, string> settings) =>
        settings.TryGetValue(AppSettingKeys.AuditTimeoutSeconds, out var raw) &&
        int.TryParse(raw, out var parsed) &&
        parsed > 0
            ? parsed
            : DefaultAuditTimeoutSeconds;
}
