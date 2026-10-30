> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 3 — PowerShell audit script

**Goal:** One script that, when run on a target PC, collects all security facts and returns **one JSON string**. It does **not** decide Pass/Fail — the C# app does that, so admins can change thresholds.

**File:** `src/SecureCheck.Web/Scripts/Invoke-SecureCheckAudit.ps1` (set to "Copy to output directory: Copy if newer").

**Rules**
- Must work in **Windows PowerShell 5.1**: no `??`, no ternary `? :`, no `ForEach-Object -Parallel`, no PS7-only cmdlets.
- Runs as admin on the target. Each section is wrapped in its own `try/catch`, so one failing section does not stop the others. On error, set that section's `error` to a short message and continue.
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
- **administrators:** group name from SID `S-1-5-32-544` (translate the SID to the local name). Try `Get-LocalGroupMember -SID 'S-1-5-32-544'`; if it throws (it can fail when the group has orphaned SIDs), fallback to ADSI: `[ADSI]"WinNT://$env:COMPUTERNAME/<groupName>,group"` and read `Members()`.
- **passwordPolicy:** `secedit /export /cfg "$env:TEMP\sc_secpol.inf" /areas SECURITYPOLICY /quiet`, read `MinimumPasswordLength`, `PasswordComplexity`, `LockoutBadCount` from the `[System Access]` section, then delete the temp file in a `finally` block. (These are the effective values, including ones applied by Group Policy.)
- **remoteRegistry:** `Get-Service RemoteRegistry` → Status, StartType (as strings). If missing, `exists = false`.
- **rdpEnabled:** `(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0`.
- **smb1:** `(Get-SmbServerConfiguration).EnableSMB1Protocol` and `(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State` (feature may not exist → `"NotPresent"`).
- **telnetClient:** `(Get-WindowsOptionalFeature -Online -FeatureName TelnetClient).State` (missing → `"NotPresent"`).

**Also create** `src/SecureCheck.Web/Scripts/README.md` explaining how to test the script by hand:
```powershell
$cred = Get-Credential
$script = Get-Content .\Invoke-SecureCheckAudit.ps1 -Raw
Invoke-Command -ComputerName 192.168.56.101 -Credential $cred -ScriptBlock ([scriptblock]::Create($script))
```

**Also create** 3 fixture files in `tests/SecureCheck.Tests/Fixtures/`: `secure-pc.json` (everything passes), `weak-pc.json` (many failures: public firewall off, guest enabled, SMB1 on, telnet on, no password rules, 90-day-old update), `partial-error.json` (antivirus section has an error, everything else fine).

**Done when**
- [ ] Running the script by hand on both VMs prints one valid JSON object (paste it into a JSON validator).
- [ ] Turning off the VM's Public firewall and re-running shows `"enabled": false` for Public.
- [ ] The script finishes in under ~30 seconds on a VM.
