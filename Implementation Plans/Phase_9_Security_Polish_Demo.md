> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 9 — Security, polish, demo testing, README

**Goal:** Make it safe, stable, and ready to demo and submit without needing any VMs.

**Tasks (AI IDE)**
1. **Security review:** every page has the correct policy (Admin pages → ManagePolicy; Run Audit, Test Connection, Acknowledge → AuditPolicy); anti-forgery tokens on all forms; HTTPS redirection + HSTS in production; no passwords in logs, exceptions, RawJson, or ActivityLog; inactive users are blocked at login; computer `HostName` validated (allow letters, digits, dots, hyphens, and `demo:weak` / `demo:secure` / `demo:error`).
2. **Activity Log page** (`Pages/Admin/ActivityLog`, Admin only): paged list with filter by user/action.
3. **Error handling:** friendly error page; validation messages on all forms; empty states ("No audits yet — go to Run Audit").
4. **Seed Demo Computers (if none exist):** In `DbSeeder`, if the `Computers` table is empty, automatically seed:
   - `My-Laptop` (`HostName = "localhost"`, `Location = "IT Office"`, `Description = "Local host machine (real PowerShell audit)"`)
   - `SC-LAB-01` (`HostName = "demo:weak"`, `Location = "Computer Lab 1"`, `Description = "Lab PC with weak security settings"`)
   - `SC-LAB-02` (`HostName = "demo:secure"`, `Location = "Computer Lab 1"`, `Description = "Hardened Lab PC"`)
5. **README.md** at the repo root: what SecureCheck is, tech stack, requirements, setup steps (SQL Express, connection string, `dotnet ef database update`, seed admin), how to audit the local machine (`localhost`), remote network PCs (WinRM), and demo endpoints, default roles, known limitations.
6. **User guide** `docs/USER_GUIDE.md`: short steps for each role (add computer, run audit, read results, apply fixes, re-audit, export report).

**Demo script (5 minutes — No VMs needed!)**
1. Log in as Admin → show **Computers** (`My-Laptop` running on `localhost`, plus `SC-LAB-01` and `SC-LAB-02`) and click **Test Connection**.
2. Run Audit on all 3 computers → show live progress bar.
3. Show **Dashboard** → `My-Laptop` (real scan of your laptop), `SC-LAB-01` (Critical risk + alert), and `SC-LAB-02` (100% Secure).
4. Open `My-Laptop` or `SC-LAB-01` → show the failed checks and the **"How to fix"** remediation box.
5. Go to **Admin > Checklist** → change a threshold (e.g., change Max Local Admins or Max Days Since Update) → re-audit `My-Laptop` live → show **"Compare with previous audit"** ("Newly failing" / "Fixed since last audit") and the score changing!
6. Export the **PDF report** and **CSV report**.
7. Log in as **Viewer** → show they can view the dashboard and export reports, but cannot run audits or access Admin pages.
