> **Paste this whole file into Antigravity (Planning mode).**
> Read `docs/PROJECT_BRIEF.md` first and follow it exactly. Do only this phase — do not start the next one.
> Before writing code, show me your plan for this phase. When finished, list the files you created or changed, run `dotnet build`, and tell me how to test this phase.

## Phase 1 — Project setup, database, login, roles, layout

**Goal:** A running Razor Pages app with SQL Server, login, three roles, a seeded admin account, and the SecureCheck look.

**Tasks**
1. Create `SecureCheck.sln`, `src/SecureCheck.Web` (Razor Pages, .NET 8, individual accounts) and `tests/SecureCheck.Tests` (xUnit, referencing the web project).
2. Add packages: EF Core SqlServer + Tools + Design (8.x), Identity EF Core + Identity UI (8.x).
3. `ApplicationUser` with `FullName` and `IsActive`. `ApplicationDbContext : IdentityDbContext<ApplicationUser>`.
4. Connection string in `appsettings.json`:
   `Server=.\\SQLEXPRESS;Database=SecureCheck;Trusted_Connection=True;TrustServerCertificate=True;MultipleActiveResultSets=true`
5. Identity: `AddDefaultIdentity<ApplicationUser>().AddRoles<IdentityRole>()`. Password rules: min 8 chars, require digit, upper, lower. Lockout after 5 failed logins for 10 minutes. `RequireConfirmedAccount = false`.
6. Scaffold only the Identity pages **Login**, **Logout**, **Manage/ChangePassword**, **AccessDenied**. Disable/remove the Register page.
7. Authorization: fallback policy requires an authenticated user; add `ManagePolicy` and `AuditPolicy` as defined in the brief. Allow anonymous only on Login and AccessDenied.
8. `DbSeeder` (runs at startup, idempotent): applies migrations, creates roles Administrator/Auditor/Viewer, creates an admin user from `appsettings.json` section `SeedAdmin` (`Email`, `Password`, `FullName`) if no user exists.
9. Layout (`_Layout.cshtml`): navy navbar with logo + "SecureCheck", nav links shown by role (Dashboard, Computers, Run Audit, Audit History, Alerts, Reports, Admin dropdown: Users, Checklist, Settings), user name + logout at right. Footer: "SecureCheck — IT23/L Project".
10. `site.css`: brand colors as CSS variables, badge classes `.risk-low/.risk-medium/.risk-high/.risk-critical/.status-error`, clean card style.
11. Add Bootstrap Icons and Chart.js 4.4.x to `wwwroot/lib` (local files).
12. Placeholder Dashboard page (`Pages/Index`) saying "Welcome, {FullName}".

**Done when**
- [ ] `dotnet build` passes; the app starts and creates the `SecureCheck` database.
- [ ] Opening the site redirects to Login; the seeded admin can log in and log out.
- [ ] There is no Register link or page.
- [ ] Navbar shows the logo and brand colors.
