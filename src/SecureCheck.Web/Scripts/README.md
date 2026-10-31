# SecureCheck PowerShell Audit Script

`Invoke-SecureCheckAudit.ps1` is a strictly **read-only** script that collects Windows security facts from the local computer (or a remote Windows PC over WinRM) and writes **one compressed JSON string** (`schemaVersion: 1`) to standard output.

- **Compatible runtimes:** Windows PowerShell 5.1 and PowerShell 7 on Windows.
- **Non-admin friendly:** Includes safe non-admin fallbacks (`net accounts`, `LanmanServer\Parameters` `SMB1` registry + `srv.sys`, and `System32\telnet.exe`) so it runs cleanly on your own laptop even when Visual Studio / PowerShell is not elevated as Administrator. When elevated as Administrator, it uses `secedit` and `Get-WindowsOptionalFeature -Online`.
- **Role:** Fact collection only (never modifies any Windows settings). Pass/Fail evaluation, thresholds, risk levels, and scores are calculated in the C# web application.
- **Bundled demo fixtures:** `Scripts/Fixtures/` (`secure-pc.json`, `weak-pc.json`, `partial-error.json`) are copied to the build output folder so simulated demo endpoints (`demo:secure`, `demo:weak`, `demo:error`) can be audited safely without modifying your laptop or needing VMs.

---

## Testing Directly on Your Laptop (Recommended)

From the repository root in PowerShell (elevated or normal user session):

```powershell
# Run directly on your own laptop (read-only):
powershell -ExecutionPolicy Bypass -File .\src\SecureCheck.Web\Scripts\Invoke-SecureCheckAudit.ps1
```

### Pretty-Print and Validate the Returned JSON

```powershell
$json = powershell -NoProfile -ExecutionPolicy Bypass -File .\src\SecureCheck.Web\Scripts\Invoke-SecureCheckAudit.ps1

# Confirm a single valid JSON object was returned and pretty-print it:
$json | ConvertFrom-Json -ErrorAction Stop | ConvertTo-Json -Depth 6
```

### Measure Execution Time (Target: < 15 Seconds)

```powershell
Measure-Command {
    $null = powershell -NoProfile -ExecutionPolicy Bypass -File .\src\SecureCheck.Web\Scripts\Invoke-SecureCheckAudit.ps1
} | Select-Object TotalSeconds
```

---

## Optional: Testing Against a Remote Network PC via WinRM

If you also test against a remote Windows PC on your network where PowerShell Remoting (`Enable-PSRemoting -Force`) is enabled:

```powershell
$cred = Get-Credential
$script = Get-Content .\src\SecureCheck.Web\Scripts\Invoke-SecureCheckAudit.ps1 -Raw
Invoke-Command -ComputerName 192.168.56.101 -Credential $cred -ScriptBlock ([scriptblock]::Create($script))
```
