using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------- Database ----------
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString));

// ---------- Data Protection (persisted keys for encrypted audit credentials) ----------
var keysDirectory = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "SecureCheck",
    "keys");
Directory.CreateDirectory(keysDirectory);

// Key files are encrypted at rest with DPAPI (see SecurityConfig).
builder.Services.AddSecureCheckDataProtection(new DirectoryInfo(keysDirectory));

builder.Services.AddSingleton<CredentialProtector>();
builder.Services.AddSingleton<PowerShellRunner>();
builder.Services.AddSingleton<AuditEvaluator>();
builder.Services.AddScoped<ActivityLogService>();

// ---------- Identity (login + roles) ----------
builder.Services
    .AddDefaultIdentity<ApplicationUser>(SecurityConfig.ConfigureIdentity)
    .AddRoles<IdentityRole>()
    .AddClaimsPrincipalFactory<AppUserClaimsPrincipalFactory>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Account/Login";
    options.LogoutPath = "/Identity/Account/Logout";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
});

// Re-check the cookie every minute so deactivated/demoted users are signed out quickly.
builder.Services.Configure<SecurityStampValidatorOptions>(SecurityConfig.ConfigureSecurityStamp);

builder.Services.Configure<SeedAdminOptions>(builder.Configuration.GetSection(SeedAdminOptions.SectionName));

// ---------- Authorization ----------
// Fallback = logged-in user; ManagePolicy = Administrator; AuditPolicy = Administrator or Auditor.
builder.Services.AddAuthorization(SecurityConfig.ConfigureAuthorization);

builder.Services.AddRazorPages(options =>
{
    // Everything under /Admin is Administrator-only.
    options.Conventions.AuthorizeFolder("/Admin", AppPolicies.Manage);
});

var app = builder.Build();

// ---------- HTTP pipeline ----------
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

// Block Identity UI pages we don't use (Register, ForgotPassword, ...) before anything else serves them.
app.UseIdentityPageAllowList();

app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

// Create/upgrade the database, roles, first admin, checklist and default settings.
await DbSeeder.SeedAsync(app.Services);

app.Run();

// Exposed for integration tests (WebApplicationFactory).
public partial class Program { }
