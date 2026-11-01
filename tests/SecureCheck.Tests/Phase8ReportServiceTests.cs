using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Infrastructure;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

public class Phase8ReportServiceTests
{
    static Phase8ReportServiceTests() => QuestPDF.Settings.License = LicenseType.Community;

    [Fact]
    public void Pure_pdf_builders_create_pdf_without_logo()
    {
        var service = Service();
        var current = Audit(1, "Weak-PC", CheckStatus.Fail, RiskLevel.Critical);
        foreach (var i in Enumerable.Range(1, 16)) current.CheckResults.Add(new CheckResult { Code = $"C{i}", Name = "Long check name", Category = CheckCategory.Firewall, RiskLevel = RiskLevel.Critical, Status = CheckStatus.Fail, ActualValue = "Off", ExpectedValue = "On", Remediation = new string('x', 400) });
        var previous = Audit(2, "Weak-PC", CheckStatus.Pass, RiskLevel.Low);
        var unreachable = Audit(3, "Offline", CheckStatus.Fail, RiskLevel.High); unreachable.Status = ComputerAuditStatus.Unreachable; unreachable.ErrorMessage = "Host unavailable";
        var run = new AuditRun { Id = 7, CreatedAt = DateTime.UtcNow, StartedByName = "Auditor", ComputerAudits = new List<ComputerAudit> { current, unreachable } };
        Assert.StartsWith("%PDF-", System.Text.Encoding.ASCII.GetString(service.BuildAuditRunPdf(run, ScoreThresholds.Default, "Viewer", DateTime.UtcNow), 0, 5));
        Assert.StartsWith("%PDF-", System.Text.Encoding.ASCII.GetString(service.BuildComputerAuditPdf(current, previous, ScoreThresholds.Default, "Viewer", DateTime.UtcNow), 0, 5));
    }

    [Fact]
    public void Csv_has_bom_headers_secure_error_row_and_formula_protection()
    {
        var secure = Audit(1, "=Formula", CheckStatus.Pass, RiskLevel.Low); secure.Score = 100; secure.OverallRisk = null;
        var offline = Audit(2, "Offline", CheckStatus.Fail, RiskLevel.High); offline.Status = ComputerAuditStatus.Unreachable; offline.ErrorMessage = "@bad host"; offline.CheckResults.Clear();
        var text = System.Text.Encoding.UTF8.GetString(Service().BuildAuditRunCsv(new AuditRun { Id = 4, ComputerAudits = new List<ComputerAudit> { secure, offline } }));
        Assert.StartsWith("\uFEFFRunId,ComputerName,HostName,Location,AuditedAt,ComputerScore,ComputerOverallRisk,CheckCode", text);
        Assert.Contains("Secure", text); Assert.Contains("Unreachable", text); Assert.Contains("'=Formula", text); Assert.Contains("'@bad host", text);
    }

    [Fact]
    public void File_names_are_safe_and_exact()
    {
        Assert.Equal("SecureCheck_Run4_20261102", ReportService.BuildRunFileName(4, new DateTime(2026, 11, 2)));
        Assert.DoesNotContain(':', ReportService.BuildComputerFileName("PC:1", new DateTime(2026, 11, 2)));
    }

    private static ReportService Service() => new(new ApplicationDbContext(new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=ignored;Trusted_Connection=True;").Options), new EmptyEnvironment());
    private static ComputerAudit Audit(int id, string name, CheckStatus status, RiskLevel risk) => new() { Id = id, ComputerId = 1, Status = ComputerAuditStatus.Completed, Score = status == CheckStatus.Pass ? 100 : 0, OverallRisk = status == CheckStatus.Fail ? risk : null, FinishedAt = DateTime.UtcNow, Computer = new Computer { Name = name, HostName = "host", Location = "Lab" }, CheckResults = new List<CheckResult> { new() { Code = "X", Name = "Check", Category = CheckCategory.Firewall, RiskLevel = risk, Status = status, ActualValue = "=bad", ExpectedValue = "On", Remediation = "Fix it" } } };
    private sealed class EmptyEnvironment : IWebHostEnvironment { public string WebRootPath { get; set; } = Path.GetTempPath(); public string ApplicationName { get; set; } = "Tests"; public string EnvironmentName { get; set; } = "Tests"; public string ContentRootPath { get; set; } = Path.GetTempPath(); public Microsoft.Extensions.FileProviders.IFileProvider WebRootFileProvider { get; set; } = null!; public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!; }
}
