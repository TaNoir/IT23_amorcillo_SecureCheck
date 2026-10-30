> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 7 — Dashboard, results, fix steps, history, alerts

**Goal:** Clear pages to see the security status of all computers, what failed, how to fix it, and how things changed over time.

**Tasks**
1. **Dashboard** (`Pages/Index`, all roles):
   - Summary cards: Total computers, Average score, Computers at High/Critical risk, Open alerts, Last audit date.
   - Doughnut chart (Chart.js): computers by overall risk (Secure, Low, Medium, High, Critical, Not audited) using brand colors.
   - Bar chart: number of failed checks per category across the latest audit of each computer.
   - Table "Computers needing attention": latest result per computer sorted by worst risk then lowest score, with links.
   - Recent alerts list (5 latest open).
2. **Audit History** (`Pages/Audits/Index`): list of runs (date, started by, computers, status, average score), paged (20 per page), filter by date range.
3. **Run Details** (`Pages/Audits/Details/{runId}`): each computer with status, score (colored), overall risk badge, passed/failed/error counts, link to computer result.
4. **Computer Result** (`Pages/Audits/Result/{computerAuditId}`):
   - Header: computer name, location, OS, audit time, big score with label, overall risk badge.
   - Results grouped by category in Bootstrap cards; each row: status icon, check name, risk badge, actual vs expected.
   - **Failed checks show a "How to fix" box** with the remediation text (commands shown in `<code>`), sorted Critical → Low.
   - **Compare with previous audit** of the same computer: list "Newly failing", "Fixed since last audit", "Still failing", plus score change (e.g. "+18").
   - Collapsible "Raw data" section with pretty-printed RawJson (Admin only).
5. **Computer History** (`Pages/Computers/History/{id}`): line chart of score over time + table of past audits.
6. **Alerts page** (`Pages/Alerts`): open/acknowledged tabs; Admin/Auditor can acknowledge (records who and when). Navbar bell icon with a badge showing the open alert count (view component).
7. Use the risk/status badge classes from Phase 1 everywhere so colors are consistent. Every page must look fine at laptop width and not break on phone width.

**Done when**
- [ ] Dashboard numbers match what is in the database for the 2 VMs.
- [ ] Weak VM result page shows failed checks with fix steps, worst first.
- [ ] After fixing one setting on the weak VM and re-auditing, the compare section shows it under "Fixed" and the score goes up.
- [ ] Acknowledging an alert removes it from the bell count.
