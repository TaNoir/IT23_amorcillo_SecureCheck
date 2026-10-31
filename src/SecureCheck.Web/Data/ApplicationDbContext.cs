using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Computer> Computers => Set<Computer>();
    public DbSet<CheckDefinition> CheckDefinitions => Set<CheckDefinition>();
    public DbSet<AuditRun> AuditRuns => Set<AuditRun>();
    public DbSet<ComputerAudit> ComputerAudits => Set<ComputerAudit>();
    public DbSet<CheckResult> CheckResults => Set<CheckResult>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<AppSetting> AppSettings => Set<AppSetting>();
    public DbSet<ActivityLog> ActivityLogs => Set<ActivityLog>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Note: bool flags (IsActive/IsEnabled) deliberately have NO database default.
        // With HasDefaultValue(true), EF treats 'false' as "not set" and the DB would save 'true'.
        // The C# initializers (= true) already give new rows the right default.

        builder.Entity<ApplicationUser>(b =>
        {
            b.Property(u => u.FullName).HasMaxLength(100).IsRequired();
        });

        builder.Entity<Computer>(b =>
        {
            b.HasIndex(c => c.Name).IsUnique();
            b.Property(c => c.LastRiskLevel).HasConversion<string>().HasMaxLength(32);
        });

        builder.Entity<CheckDefinition>(b =>
        {
            b.HasIndex(c => c.Code).IsUnique();
            b.Property(c => c.Category).HasConversion<string>().HasMaxLength(40);
            b.Property(c => c.RiskLevel).HasConversion<string>().HasMaxLength(32);
        });

        builder.Entity<AuditRun>(b =>
        {
            b.Property(r => r.Status).HasConversion<string>().HasMaxLength(40);
            b.HasIndex(r => r.CreatedAt);
        });

        builder.Entity<ComputerAudit>(b =>
        {
            b.Property(ca => ca.Status).HasConversion<string>().HasMaxLength(40);
            b.Property(ca => ca.OverallRisk).HasConversion<string>().HasMaxLength(32);
            b.Property(ca => ca.RawJson).HasColumnType("nvarchar(max)");

            b.HasOne(ca => ca.AuditRun)
                .WithMany(r => r.ComputerAudits)
                .HasForeignKey(ca => ca.AuditRunId)
                .OnDelete(DeleteBehavior.Cascade);

            // Prevent deleting a computer that already has audit history; deactivate instead.
            b.HasOne(ca => ca.Computer)
                .WithMany(c => c.ComputerAudits)
                .HasForeignKey(ca => ca.ComputerId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        builder.Entity<CheckResult>(b =>
        {
            b.Property(cr => cr.Category).HasConversion<string>().HasMaxLength(40);
            b.Property(cr => cr.RiskLevel).HasConversion<string>().HasMaxLength(32);
            b.Property(cr => cr.Status).HasConversion<string>().HasMaxLength(32);

            b.HasOne(cr => cr.ComputerAudit)
                .WithMany(ca => ca.CheckResults)
                .HasForeignKey(cr => cr.ComputerAuditId)
                .OnDelete(DeleteBehavior.Cascade);

            b.HasOne(cr => cr.CheckDefinition)
                .WithMany(cd => cd.CheckResults)
                .HasForeignKey(cr => cr.CheckDefinitionId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        builder.Entity<Alert>(b =>
        {
            b.Property(a => a.Severity).HasConversion<string>().HasMaxLength(32);
            b.HasIndex(a => new { a.IsAcknowledged, a.CreatedAt });

            b.HasOne(a => a.ComputerAudit)
                .WithMany(ca => ca.Alerts)
                .HasForeignKey(a => a.ComputerAuditId)
                .OnDelete(DeleteBehavior.Cascade);

            b.HasOne(a => a.Computer)
                .WithMany(c => c.Alerts)
                .HasForeignKey(a => a.ComputerId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        builder.Entity<AppSetting>(b =>
        {
            b.HasKey(s => s.Key);
        });

        builder.Entity<ActivityLog>(b =>
        {
            b.HasIndex(l => l.CreatedAt);
        });
    }
}
