> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 2 — Data model and management pages

**Goal:** All entities from the brief exist in the database, the checklist is seeded, and Administrators can manage computers, users, the checklist, and settings.

**Tasks**
1. Add all entities and enums from the brief's **Data model**. Configure: unique index on `Computer.Name` and `CheckDefinition.Code`; enums stored as strings; cascade delete AuditRun → ComputerAudit → CheckResult; **restrict** delete of Computer if it has audits (use `IsActive = false` instead).
2. Migration `AddCoreEntities`.
3. Extend `DbSeeder`: insert the 16 checks from the brief's checklist table (match by `Code`; insert missing ones only, never overwrite admin edits). Insert default AppSettings if missing.
4. `CredentialProtector` service using ASP.NET Core Data Protection (purpose `"SecureCheck.Credentials"`). Persist keys to `%LOCALAPPDATA%\SecureCheck\keys` (`PersistKeysToFileSystem`) so encrypted passwords still work after restart. Methods: `Protect(string)`, `Unprotect(string)`.
5. `ActivityLogService.LogAsync(userName, action, details)`.
6. **Computers pages** (`Pages/Computers`): list (search + filter by Location + active/inactive), Create, Edit, Deactivate/Activate. Fields: Name, HostName, Location, Description, optional credential (username + password; leave password blank on edit = keep current). Show "Uses default credential" when none set. Admin only for create/edit; everyone can see the list.
7. **Users page** (`Pages/Admin/Users`): list users with role; create user (full name, email, role, temp password); change role; reset password; deactivate (set `IsActive = false` and lock out). Block deactivating yourself. Inactive users cannot log in.
8. **Checklist page** (`Pages/Admin/Checklist`): table grouped by category; edit Risk Level (dropdown), Threshold (only if the check has one), Remediation text, Enabled toggle. Code and Name are read-only.
9. **Settings page** (`Pages/Admin/Settings`): Default audit credential (username + password, password write-only), Max parallel audits (1–20), Audit timeout seconds (30–600), score label thresholds.
10. Log every create/edit/delete above to ActivityLog.

**Done when**
- [ ] Database has all tables; 16 checks and default settings are seeded once (restarting does not duplicate them).
- [ ] Admin can add the 2 lab VMs as computers (HostName = their IPs, Location = "Lab 1").
- [ ] Admin can create one Auditor and one Viewer user; those users cannot open `/Admin/*` (they see Access Denied).
- [ ] Passwords never appear in the page HTML, logs, or database in plain text.
