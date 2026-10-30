> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 6 — Running audits (background), saving results, alerts

**Goal:** Auditors pick computers, start an audit, watch progress live, and results are saved as history. High/Critical results create alerts.

**Tasks**
1. `AuditQueue` (singleton) using `System.Threading.Channels.Channel<int>` of AuditRun IDs.
2. `AuditWorker : BackgroundService`: reads run IDs; for each run sets status Running, then audits its computers **in parallel** limited by `MaxParallelAudits` (`SemaphoreSlim`). Use a new DI scope / DbContext per computer (DbContext is not thread-safe).
3. For each computer: set `ComputerAudit.Status = Running` → call `PowerShellRunner.RunAuditAsync` → on success deserialize + evaluate + save `CheckResult` rows (with snapshots), `Score`, `OverallRisk`, counts, OS info, `RawJson`, status Completed; on failure save status Unreachable (for Unreachable/AccessDenied/NotTrusted/Timeout) or Failed (bad JSON/other) with the friendly message. Update `Computer.LastAuditedAt/LastScore/LastRiskLevel` on success. Increment `AuditRun.CompletedComputers`.
4. When all computers finish: run status = Completed, or CompletedWithErrors if any were Unreachable/Failed; set `FinishedAt`.
5. On app start, mark any runs left in Queued/Running (app crashed) as CompletedWithErrors with message "Interrupted — app restarted".
6. `AlertService`: after each successful computer audit with OverallRisk High or Critical, create an Alert, e.g. "SC-LAB-01: 3 Critical and 2 High findings (score 41)".
7. **Run Audit page** (`Pages/Audits/Run`, AuditPolicy): list of active computers with checkboxes, "Select all", filter by Location, last score/risk badges. "Start Audit" creates the AuditRun + ComputerAudit rows (Pending), enqueues it, and redirects to the progress page. Validate at least one computer is selected.
8. **Progress page** (`Pages/Audits/Progress/{runId}`): progress bar + table of computers with status badges; a JSON handler (`OnGetStatus`) polled every 2 seconds with `fetch`. When finished, show a button "View Results".
9. Prevent auditing the same computer twice at the same time (skip it with a message if it already has a Running/Pending audit).
10. ActivityLog: "Started audit run #N on X computers".

**Done when**
- [ ] Auditing both VMs at once works; progress updates without refreshing the page.
- [ ] One VM turned off → that row becomes "Unreachable" with a clear message, the other completes, run = CompletedWithErrors.
- [ ] Results are in the database; the weak VM (after Phase 9 lab script, or after manually turning things off) creates an alert.
- [ ] A Viewer cannot open the Run Audit page.
