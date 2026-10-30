> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 4 — C# PowerShell runner and "Test Connection"

**Goal:** The web app can run the audit script on a computer and get the JSON back, with clear error messages when it fails.

**Tasks**
1. Add `Microsoft.PowerShell.SDK` **7.4.x**.
2. `PowerShellRunner` service (singleton), method:
   `Task<RunnerResult> RunAuditAsync(string hostName, string userName, string password, int timeoutSeconds, CancellationToken ct)`
   - Load script text from `Scripts/Invoke-SecureCheckAudit.ps1` once (from `AppContext.BaseDirectory`).
   - Create a **local** runspace with `InitialSessionState.CreateDefault2()` and execution policy Bypass (process scope).
   - Build a `PSCredential` (password as `SecureString`) and run `Invoke-Command` with `PowerShell.AddCommand("Invoke-Command")` and `AddParameter` calls:
     `ComputerName` = host, `Credential` = the PSCredential, `ScriptBlock` = `ScriptBlock.Create(scriptText)`, `SessionOption` = `new PSSessionOption { OpenTimeout = 15s, OperationTimeout = timeout }`, `ErrorAction` = `Stop`.
     Never build PowerShell code by string-concatenating user input (host names, user names).
   - Enforce the timeout with a `CancellationTokenSource`; on timeout call `PowerShell.Stop()`.
   - Return `RunnerResult { Success, Json, ErrorMessage, ErrorKind, Duration }`.
   - `ErrorKind` + friendly message mapping (check the exception text):
     - "Access is denied" → `AccessDenied`: "Login failed or the account is not an administrator on this computer."
     - "WinRM cannot complete the operation" / "cannot connect" → `Unreachable`: "Computer is off, not on the network, or remote PowerShell is not turned on."
     - "TrustedHosts" → `NotTrusted`: "This computer is not in the TrustedHosts list (workgroup networks only)."
     - timeout → `Timeout`; anything else → `Other` with the original message.
3. `RunTestAsync(...)` — same, but runs only `$env:COMPUTERNAME; $PSVersionTable.PSVersion.ToString()` and returns them.
4. Credential choice helper: use the computer's own credential if set, otherwise the default credential from AppSettings; if neither exists, return a clear error "No audit credential set — add one in Settings."
5. Add a **Test Connection** button on the Computers list and edit page (AuditPolicy). It calls a page handler, shows a green alert "Connected to SC-LAB-01 (PowerShell 5.1)" or a red alert with the friendly message.
6. Add a small **Diagnostics** page (Admin only) where you pick a computer and click "Run script" to see the raw JSON (pretty-printed) — useful for debugging.
7. Log test connections to ActivityLog (no passwords).

> Fallback if the SDK gives trouble: run `powershell.exe -NoProfile -NonInteractive -EncodedCommand ...` with `System.Diagnostics.Process` and read stdout. Only use this if the SDK approach truly fails, and keep the same `RunnerResult` interface.

**Done when**
- [ ] Test Connection succeeds for both VMs and shows their names.
- [ ] Wrong password → "Login failed..." message (no crash). VM turned off → "Computer is off..." message within ~20 seconds.
- [ ] Diagnostics page shows the same JSON as running the script by hand.
