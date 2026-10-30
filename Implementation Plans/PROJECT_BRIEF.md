# SecureCheck — Project Brief

### What SecureCheck is
A web app for a school/university IT department. IT staff pick Windows computers (lab and office PCs), and the app connects to them through PowerShell Remoting, collects their security settings, compares them against a security checklist, gives each failed check a risk level (Low, Medium, High, Critical), computes a security score, recommends simple fix steps, saves everything as audit history, shows a dashboard with alerts, and exports PDF/CSV reports.

### Tech stack (do not change)
- **.NET 8 (LTS)**, **ASP.NET Core Razor Pages**, C#. Single web project. **Runs on Windows only.**
- **Microsoft.PowerShell.SDK 7.4.x** (this version line targets .NET 8 — keep them matched).
- **Entity Framework Core 8** with **SQL Server Express** (`Microsoft.EntityFrameworkCore.SqlServer`).
- **ASP.NET Core Identity** (`Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.AspNetCore.Identity.UI`) for login and roles.
- **Bootstrap 5** (comes with the template), **Bootstrap Icons**, **Chart.js 4.4.x** (local copy in `wwwroot/lib`, no CDN).
- **QuestPDF** (set `QuestPDF.Settings.License = LicenseType.Community;` at startup) for PDF.
- **CsvHelper** for CSV.
- **xUnit** test project for the evaluation engine.
- The audit script is **Windows PowerShell 5.1 compatible** (it runs on the target PCs, which have 5.1).

### Solution layout
```
SecureCheck.sln
src/SecureCheck.Web/
  Data/              ApplicationDbContext.cs, DbSeeder.cs, Migrations/
  Models/            entity classes + enums
  Services/          PowerShellRunner.cs, AuditEvaluator.cs, AuditQueue.cs, AuditWorker.cs,
                     CredentialProtector.cs, ReportService.cs, AlertService.cs
  Scripts/           Invoke-SecureCheckAudit.ps1   (copied to output folder)
  Pages/             Index (Dashboard), Computers/, Audits/, Alerts/, Reports/, Admin/
  wwwroot/           css/site.css, js/, img/logo.png, lib/
tests/SecureCheck.Tests/
  Fixtures/          sample audit JSON files
docs/PROJECT_BRIEF.md
lab/                 Make-WeakPC.ps1 (Phase 9, for test VMs only)
```

### User roles
| Role | Who | Can do |
|---|---|---|
| **Administrator** | System Administrators | Everything: manage computers, users, checklist, settings; run audits; view and export. |
| **Auditor** | IT Support Staff, IT Security Officers | Run audits, test connections, view results and fixes, acknowledge alerts, export reports. |
| **Viewer** | IT Department Heads | View dashboard, audit history, results and alerts; view and export reports. Cannot run audits or change anything. |

Authorization policies: `ManagePolicy` = Administrator; `AuditPolicy` = Administrator or Auditor; everyone else must simply be logged in (fallback policy = authenticated user). No public registration page.

### Data model (EF Core entities)
- **ApplicationUser** : IdentityUser — `FullName`, `IsActive`.
- **Computer** — `Id`, `Name` (display, unique), `HostName` (DNS name or IP), `Location` (e.g. "Lab 1"), `Description`, `IsActive`, `CredentialUserName` (nullable), `CredentialPasswordProtected` (nullable, encrypted), `CreatedAt`, `LastAuditedAt`, `LastScore`, `LastRiskLevel`.
- **CheckDefinition** — `Id`, `Code` (unique, e.g. `FW-PUBLIC`), `Name`, `Category` (enum), `Description`, `RiskLevel` (enum), `Threshold` (int?, nullable), `ThresholdLabel` (e.g. "Max days since last update"), `Remediation` (text), `IsEnabled`, `SortOrder`.
- **AuditRun** — `Id`, `StartedByUserId`, `StartedByName`, `CreatedAt`, `StartedAt`, `FinishedAt`, `Status` (enum), `TotalComputers`, `CompletedComputers`.
- **ComputerAudit** — `Id`, `AuditRunId`, `ComputerId`, `Status` (enum), `StartedAt`, `FinishedAt`, `Score` (int?), `OverallRisk` (RiskLevel?), `PassedCount`, `FailedCount`, `ErrorCount`, `ErrorMessage`, `OsCaption`, `OsVersion`, `PsVersion`, `RawJson` (nvarchar(max)).
- **CheckResult** — `Id`, `ComputerAuditId`, `CheckDefinitionId`, and **snapshot copies** of `Code`, `Name`, `Category`, `RiskLevel`, `Remediation` (so editing the checklist later never changes old history), plus `Status` (enum), `ActualValue`, `ExpectedValue`, `Message`.
- **Alert** — `Id`, `ComputerId`, `ComputerAuditId`, `Severity` (RiskLevel), `Message`, `CreatedAt`, `IsAcknowledged`, `AcknowledgedByName`, `AcknowledgedAt`.
- **AppSetting** — `Key` (PK), `Value`. Keys: `DefaultCredentialUserName`, `DefaultCredentialPasswordProtected`, `MaxParallelAudits` (default 5), `AuditTimeoutSeconds` (default 180), `ScoreGoodMin` (90), `ScoreFairMin` (70), `ScorePoorMin` (50).
- **ActivityLog** — `Id`, `UserName`, `Action`, `Details`, `CreatedAt`.

Enums (store as strings in the DB with `.HasConversion<string>()`):
- `CheckCategory`: Firewall, Updates, Antivirus, Accounts, ServicesAndFeatures
- `RiskLevel`: Low = 1, Medium = 2, High = 3, Critical = 4
- `AuditRunStatus`: Queued, Running, Completed, CompletedWithErrors
- `ComputerAuditStatus`: Pending, Running, Completed, Unreachable, Failed
- `CheckStatus`: Pass, Fail, Error, Skipped

### The checklist (seed data — 16 checks)
| Code | Name | Category | Risk | Threshold | Passes when | Remediation (seed text) |
|---|---|---|---|---|---|---|
| FW-DOMAIN | Firewall on (Domain profile) | Firewall | High | — | Domain profile enabled | Open Windows Security > Firewall & network protection and turn on the Domain network firewall. Or run as admin: `Set-NetFirewallProfile -Profile Domain -Enabled True` |
| FW-PRIVATE | Firewall on (Private profile) | Firewall | High | — | Private profile enabled | Turn on the Private network firewall in Windows Security. Or run: `Set-NetFirewallProfile -Profile Private -Enabled True` |
| FW-PUBLIC | Firewall on (Public profile) | Firewall | Critical | — | Public profile enabled | Turn on the Public network firewall in Windows Security. Or run: `Set-NetFirewallProfile -Profile Public -Enabled True` |
| UPD-RECENT | Recent Windows update installed | Updates | High | 30 (max days since last update) | Days since last installed update ≤ threshold | Go to Settings > Windows Update > Check for updates, install all updates, then restart the computer. |
| AV-ENABLED | Antivirus turned on | Antivirus | Critical | — | `AntivirusEnabled` is true | Open Windows Security > Virus & threat protection and turn it on. If another antivirus is installed, make sure it is active and up to date. |
| AV-REALTIME | Real-time protection on | Antivirus | High | — | `RealTimeProtectionEnabled` is true | Windows Security > Virus & threat protection > Manage settings > turn on Real-time protection. Or run: `Set-MpPreference -DisableRealtimeMonitoring $false` |
| AV-SIGNATURES | Virus definitions up to date | Antivirus | Medium | 7 (max days old) | Signature age ≤ threshold | Windows Security > Virus & threat protection > Check for updates. Or run: `Update-MpSignature` |
| ACC-GUEST | Guest account disabled | Accounts | High | — | Guest account (SID ending -501) disabled or missing | Run as admin: `Get-LocalUser \| Where-Object SID -like '*-501' \| Disable-LocalUser` |
| ACC-ADMINS | Limited number of admin accounts | Accounts | Medium | 2 (max admins) | Members of local Administrators ≤ threshold | Open `lusrmgr.msc` > Groups > Administrators and remove accounts that do not need admin rights. Or run: `Remove-LocalGroupMember -Group Administrators -Member <name>` |
| ACC-PWLENGTH | Minimum password length set | Accounts | Medium | 8 (min characters) | Minimum password length ≥ threshold | Open `secpol.msc` > Account Policies > Password Policy > Minimum password length = 8 or more. Or run: `net accounts /minpwlen:8`. In a domain, set it in Group Policy. |
| ACC-PWCOMPLEX | Password complexity turned on | Accounts | Medium | — | PasswordComplexity = 1 | Open `secpol.msc` > Account Policies > Password Policy > enable "Password must meet complexity requirements". In a domain, set it in Group Policy. |
| ACC-LOCKOUT | Account lockout turned on | Accounts | Medium | 10 (max failed attempts) | Lockout threshold is between 1 and the threshold | Open `secpol.msc` > Account Policies > Account Lockout Policy > set threshold to 5. Or run: `net accounts /lockoutthreshold:5` |
| SVC-REMOTEREG | Remote Registry service off | ServicesAndFeatures | Medium | — | Service not running and not set to Automatic | Run as admin: `Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled` |
| SVC-RDP | Remote Desktop turned off | ServicesAndFeatures | Medium | — | `fDenyTSConnections` = 1 | Settings > System > Remote Desktop > Off. If Remote Desktop is really needed, allow only specific users and keep Network Level Authentication on. |
| SVC-SMB1 | SMBv1 protocol turned off | ServicesAndFeatures | Critical | — | SMB1 server protocol disabled **and** SMB1Protocol feature not Enabled | Run as admin: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` and `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`, then restart. |
| SVC-TELNET | Telnet Client feature turned off | ServicesAndFeatures | Low | — | TelnetClient feature not Enabled | Run as admin: `Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart` |

If a fact could not be collected, the check's status is **Error** (not Fail) and it is left out of the score.

### Scoring rules
- Weights: Low = 1, Medium = 2, High = 3, Critical = 4.
- **Score** = round(100 × sum of weights of **Pass** checks ÷ sum of weights of **Pass + Fail** checks). Error/Skipped checks are excluded. If nothing was evaluated, score is null.
- **Overall risk** = the highest `RiskLevel` among Failed checks. No failures = shown as "Secure".
- Score label: ≥ 90 Good (green), 70–89 Fair (yellow), 50–69 Poor (orange), < 50 Critical (red). Thresholds come from AppSettings.
- **Alert** is created for a computer audit when its overall risk is High or Critical.

### Brand colors (from the logo)
- Navy `#0A3061` (navbar, headings, primary buttons)
- Green `#168653` (Low / Pass / Good)
- Yellow `#E5B72E` (Medium / Fair)
- Orange `#EC8A3C` (High / Poor)
- Red `#F45D5B` (Critical / Fail)
- Gray `#8A94A6` (Error / Unreachable)
Logo file: `wwwroot/img/logo.png` (the developer will copy it in).

### Rules for the AI IDE (follow in every phase)
- Do only the current phase. Do not rename things defined in this brief.
- Use only the packages listed above. Do not invent package names or APIs. If unsure about an API, say so.
- Keep code simple and readable (student project). Add short comments on non-obvious parts.
- Use async/await for DB and PowerShell calls. Use dependency injection.
- Never log or display passwords. Store credentials only encrypted (ASP.NET Core Data Protection).
- `dotnet build` must pass with no errors at the end of every phase. If you add EF changes, add a migration.
- At the end of the phase, list the files you created/changed and how to test the phase.
