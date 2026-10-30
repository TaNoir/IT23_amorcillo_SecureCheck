> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 9 — Security, polish, demo testing, README

**Goal:** Make it safe, stable, and ready to demo and submit.

**Tasks (AI IDE)**
1. **Security review:** every page has the correct policy (Admin pages → ManagePolicy; Run Audit, Test Connection, Acknowledge → AuditPolicy); anti-forgery tokens on all forms; HTTPS redirection + HSTS in production; no passwords in logs, exceptions, RawJson, or ActivityLog; inactive users are blocked at login; computer `HostName` validated (letters, digits, dots, hyphens only).
2. **Activity Log page** (`Pages/Admin/ActivityLog`, Admin only): paged list with filter by user/action.
3. **Error handling:** friendly error page; validation messages on all forms; empty states ("No audits yet — go to Run Audit").
4. **Lab script** `lab/Make-WeakPC.ps1` — **for test VMs only**, with a big warning comment at the top and a confirmation prompt. It makes a VM fail most checks for the demo: turns off the Public firewall profile, enables the Guest account, adds a second local admin, sets min password length 0 and lockout 0, starts Remote Registry, enables Remote Desktop, enables SMB1 and Telnet Client. Also `lab/Make-SecurePC.ps1` that reverses all of it.
5. **README.md** at the repo root: what SecureCheck is, tech stack, requirements, setup steps (SQL Express, connection string, `dotnet ef database update`, seed admin), lab setup summary (Phase 0), how to run, default roles, screenshots placeholders, known limitations (Windows only; workgroup PCs need TrustedHosts; Defender-based antivirus checks).
6. **User guide** `docs/USER_GUIDE.md`: short steps for each role (add computer, run audit, read results, apply fixes, re-audit, export report).

**Tasks (you)**
- [ ] Run `Make-WeakPC.ps1` on SC-LAB-01 and `Make-SecurePC.ps1` on SC-LAB-02, then audit both.
- [ ] Check: weak PC = Critical with low score + alert; secure PC = high score.
- [ ] Apply 2–3 fixes on SC-LAB-01 using the app's fix steps, re-audit, confirm the comparison shows "Fixed".
- [ ] Log in as Auditor and Viewer and confirm each can only do what the roles table says.
- [ ] Export a PDF and CSV for your documentation.
- [ ] Take screenshots of the dashboard, a result page, and a PDF report.

**Demo script (5 minutes)**
1. Log in as Admin → show Computers and the Checklist (change a threshold to show it is editable).
2. Run Audit on both VMs → show live progress.
3. Dashboard → weak vs secure PC, alert bell.
4. Open the weak PC → failed checks + "How to fix".
5. Fix one setting on the VM live → re-audit → show "Fixed since last audit" and the score going up.
6. Export the PDF report.
7. Log in as Viewer → show they can view and export but cannot run audits.
