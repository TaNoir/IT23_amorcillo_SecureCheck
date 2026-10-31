> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 4 — C# PowerShell runner and "Test Connection"

**Goal:** The web app can run the audit script on the local laptop, on remote computers via WinRM, or on built-in simulated demo endpoints, and get the JSON back with clear error messages when it fails.

**Tasks**
1. Add `Microsoft.PowerShell.SDK` **7.4.x**.
2. `PowerShellRunner` service (singleton), method:
   `Task<RunnerResult> RunAuditAsync(string hostName, string userName, string password, int timeoutSeconds, CancellationToken ct)`
   - Load script text from `Scripts/Invoke-SecureCheckAudit.ps1` once (from `AppContext.BaseDirectory`).
   - Support **3 execution modes** based on `hostName` (trimmed, case-insensitive):
     - **Mode A — Local Machine (`localhost`, `127.0.0.1`, `.`, or matching `Environment.MachineName`):**
       Run the script **directly on the local machine** without WinRM and without requiring credentials (either via a local PowerShell SDK runspace executing `scriptText` directly, or `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ...` capturing stdout). This allows auditing the developer's own laptop immediately even on Windows 11 with a PIN/Microsoft Account.
     - **Mode B — Built-in Demo Endpoints (`demo:weak`, `demo:secure`, `demo:error`):**
       Wait 1–2 seconds (to simulate scan progress) and return the matching JSON from `Scripts/Fixtures/weak-pc.json`, `secure-pc.json`, or `partial-error.json`. Does not require credentials. This allows safe testing of weak/failing configurations without VMs or weakening the developer's laptop.
     - **Mode C — Remote Network Computer (any other hostname or IP):**
       Require credentials (use the computer's own credential if set, otherwise the default credential from AppSettings; if neither exists, return a clear error "No audit credential set — add one in Settings."). Build a `PSCredential` (password as `SecureString`) and run `Invoke-Command` with `PowerShell.AddCommand("Invoke-Command")` and `AddParameter` calls (`ComputerName`, `Credential`, `ScriptBlock`, `SessionOption`, `ErrorAction = Stop`). Never build PowerShell code by string-concatenating user input.
   - Enforce the timeout with a `CancellationTokenSource`.
   - Return `RunnerResult { Success, Json, ErrorMessage, ErrorKind, Duration }`.
   - `ErrorKind` + friendly message mapping (check the exception text):
     - "Access is denied" → `AccessDenied`: "Login failed or the account is not an administrator on this computer."
     - "WinRM cannot complete the operation" / "cannot connect" → `Unreachable`: "Computer is off, not on the network, or remote PowerShell is not turned on."
     - "TrustedHosts" → `NotTrusted`: "This computer is not in the TrustedHosts list (workgroup networks only)."
     - timeout → `Timeout`; anything else → `Other` with the original message.
3. `RunTestAsync(...)`:
   - For Mode A (`localhost` / local machine): returns `Environment.MachineName` and local PowerShell version.
   - For Mode B (`demo:*`): returns simulated computer name (`SC-LAB-01` / `SC-LAB-02`) and `"5.1 (Simulated Endpoint)"`.
   - For Mode C (remote computer): runs `$env:COMPUTERNAME; $PSVersionTable.PSVersion.ToString()` via `Invoke-Command`.
4. Add a **Test Connection** button on the Computers list and edit page (AuditPolicy). It calls a page handler, shows a green alert "Connected to {ComputerName} (PowerShell {Version})" or a red alert with the friendly message.
5. Add a small **Diagnostics** page (Admin only) where you pick a computer and click "Run script" to see the raw JSON (pretty-printed) — useful for debugging.
6. Log test connections to ActivityLog (no passwords).

**Done when**
- [ ] Adding your own laptop (`HostName = localhost`, Location = `"My Laptop"`) and clicking Test Connection succeeds immediately without needing a password.
- [ ] Adding `SC-LAB-01` (`HostName = demo:weak`) and `SC-LAB-02` (`HostName = demo:secure`) and clicking Test Connection succeeds.
- [ ] Adding an unreachable IP (e.g. `192.168.99.99`) shows the friendly "Computer is off..." message within ~20 seconds.
- [ ] Diagnostics page shows your laptop's real JSON when running on `localhost`.
