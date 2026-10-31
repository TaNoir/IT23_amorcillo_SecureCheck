> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 3 — PowerShell audit script

**Goal:** One read-only script that, when run on a target PC (or the local laptop), collects all security facts and returns **one JSON string**. It does **not** decide Pass/Fail and never modifies any computer settings — the C# app decides Pass/Fail, so admins can change thresholds.

**File:** `src/SecureCheck.Web/Scripts/Invoke-SecureCheckAudit.ps1` (set to "Copy to output directory: Copy if newer").

**Rules**
- Must work in **Windows PowerShell 5.1** and **PowerShell 7**: no `ForEach-Object -Parallel`, no PS7-only cmdlets.
- Strictly read-only (never change any Windows settings). Each section is wrapped in its own `try/catch`, so one failing section does not stop the others. On error, set that section's `error` to a short message and continue.
- Include safe non-admin fallbacks so the script works on the local laptop even when not elevated as Administrator.
- Output: `ConvertTo-Json -Depth 6 -Compress`, written as the **only** output. Dates as ISO strings (`.ToString("o")`).
- Use SIDs instead of names where possible (works on non-English Windows).

**JSON contract (exact shape)**
```json
{
  "schemaVersion": 1,
  "computerName": "SC-LAB-01",
  "collectedAt": "2026-10-29T09:00:00.0000000+08:00",
  "os": { "caption": "Microsoft Windows 11 Enterprise Evaluation", "version": "10.0.22631", "psVersion": "5.1.22621.4391", "psMajor": 5 },
  "firewall": { "error": null, "profiles": [ { "name": "Domain", "enabled": true }, { "name": "Private", "enabled": true }, { "name": "Public", "enabled": false } ] },
  "updates": { "error": null, "lastInstalledOn": "2026-10-10T00:00:00.0000000", "latestHotFixId": "KB5031455", "hotFixCount": 14, "source": "Get-HotFix" },
  "antivirus": { "error": null, "antivirusEnabled": true, "realTimeProtectionEnabled": true, "signatureAgeDays": 1, "signatureLastUpdated": "2026-10-28T20:00:00.0000000" },
  "accounts": {
    "error": null,
    "guest": { "exists": true, "enabled": false },
    "administrators": { "count": 2, "members": [ "SC-LAB-01\\Administrator", "SC-LAB-01\\scaudit" ] },
    "passwordPolicy": { "minimumPasswordLength": 0, "passwordComplexity": 0, "lockoutBadCount": 0, "source": "secedit" }
  },
  "servicesAndFeatures": {
    "error": null,
    "remoteRegistry": { "exists": true, "status": "Stopped", "startType": "Manual" },
    "rdpEnabled": false,
    "smb1": { "serverProtocolEnabled": false, "featureState": "Disabled" },
    "telnetClient": { "featureState": "Disabled" }
  }
}
```
Use `null` for a value that could not be read. Sub-parts inside `accounts` and `servicesAndFeatures` may each set their own `error` field if only that part fails (e.g. `"smb1": { "error": "..." }`).

**How to collect each fact**
- **os:** `Get-CimInstance Win32_OperatingSystem` (Caption, Version); `$PSVersionTable.PSVersion`.
- **firewall:** `Get-NetFirewallProfile | Select-Object Name, Enabled`. Convert `Enabled` to a real boolean.
- **updates:** `Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1`. If no hotfix has a date, fallback: `(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()` → `QueryHistory(0, 1)` and use its `Date`; set `"source": "WindowsUpdateHistory"`.
- **antivirus:** `Get-MpComputerStatus` → `AntivirusEnabled`, `RealTimeProtectionEnabled`, `AntivirusSignatureAge`, `AntivirusSignatureLastUpdated`. If the cmdlet is missing or fails, set `error` = "Windows Defender status not available (another antivirus may be installed)".
- **guest:** `Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }`.
- **administrators:** group name from SID `S-1-5-32-544` (translate the SID to the local name). Try `Get-LocalGroupMember -SID 'S-1-5-32-544'`; if it throws (it can fail when the group has orphaned SIDs or Microsoft accounts), fallback to ADSI: `[ADSI]"WinNT://$env:COMPUTERNAME/<groupName>,group"` and read `Members()`.
- **passwordPolicy:** Try `secedit /export /cfg "$env:TEMP\sc_secpol.inf" /areas SECURITYPOLICY /quiet`, read `MinimumPasswordLength`, `PasswordComplexity`, `LockoutBadCount` from `[System Access]`, and delete the temp file in `finally`. Fallback if not running as Admin (or if `secedit` fails): parse `net accounts` output for `Minimum password length` and `Lockout threshold` (default `passwordComplexity` to 0 and set `"source": "net accounts"`).
- **remoteRegistry:** `Get-Service RemoteRegistry` → Status, StartType (as strings). If missing, `exists = false`.
- **rdpEnabled:** `(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0`.
- **smb1:** Try `(Get-SmbServerConfiguration).EnableSMB1Protocol` (fallback to reading registry `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` value `SMB1` — if missing or 0, false). For `featureState`, try `(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State`; if not running as Admin, fallback to checking if `C:\Windows\System32\drivers\srv.sys` exists or default to `"Disabled"` when `serverProtocolEnabled` is false.
- **telnetClient:** Try `(Get-WindowsOptionalFeature -Online -FeatureName TelnetClient).State`; if not running as Admin, fallback to checking `Test-Path "$env:SystemRoot\System32\telnet.exe"` (true → `"Enabled"`, false → `"Disabled"`).

**Also create** `src/SecureCheck.Web/Scripts/README.md` explaining how to test the script by hand locally on your laptop (and optionally over remote PowerShell):
```powershell
# Run directly on your own laptop (read-only):
powershell -ExecutionPolicy Bypass -File .\src\SecureCheck.Web\Scripts\Invoke-SecureCheckAudit.ps1
```

**Also create** 3 fixture files in `tests/SecureCheck.Tests/Fixtures/`: `secure-pc.json` (everything passes), `weak-pc.json` (many failures: public firewall off, guest enabled, SMB1 on, telnet on, no password rules, 90-day-old update), `partial-error.json` (antivirus section has an error, everything else fine). Also copy these 3 fixture JSON files into `src/SecureCheck.Web/Scripts/Fixtures/` (set to Copy if newer) so they can be used for built-in demo endpoints later.

**Done when**
- [ ] Running `Invoke-SecureCheckAudit.ps1` on your laptop prints one valid JSON object with your laptop's real security settings.
- [ ] The script finishes in under ~15 seconds and does not modify anything on your laptop.
