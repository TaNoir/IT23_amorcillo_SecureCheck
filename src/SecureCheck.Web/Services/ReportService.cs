using System.Globalization;
using System.Text;
using CsvHelper;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>Creates export documents from audit snapshots. RawJson and credentials are never loaded.</summary>
public sealed class ReportService
{
    private const string Navy = "#0A3061";
    private const string Green = "#168653";
    private const string Gray = "#8A94A6";
    private readonly ApplicationDbContext _db;
    private readonly IWebHostEnvironment _environment;

    public ReportService(ApplicationDbContext db, IWebHostEnvironment environment)
    {
        _db = db;
        _environment = environment;
    }

    public async Task<byte[]?> BuildAuditRunPdfAsync(int auditRunId, string generatedBy, DateTime generatedAtUtc, CancellationToken ct = default)
    {
        var run = await LoadRunAsync(auditRunId, ct);
        return run is null ? null : BuildAuditRunPdf(run, await ScoreThresholds.LoadAsync(_db, ct), generatedBy, generatedAtUtc);
    }

    public async Task<byte[]?> BuildAuditRunCsvAsync(int auditRunId, CancellationToken ct = default)
    {
        var run = await LoadRunAsync(auditRunId, ct);
        return run is null ? null : BuildAuditRunCsv(run);
    }

    public async Task<byte[]?> BuildComputerAuditPdfAsync(int computerAuditId, string generatedBy, DateTime generatedAtUtc, CancellationToken ct = default)
    {
        var audit = await LoadComputerAuditAsync(computerAuditId, ct);
        if (audit is null) return null;
        ComputerAudit? previous = null;
        if (audit.Status == ComputerAuditStatus.Completed)
        {
            previous = await AuditAnalyticsService.BuildPreviousCompletedAuditQuery(_db.ComputerAudits.AsNoTracking(), audit)
                .Select(ca => new ComputerAudit { Id = ca.Id, ComputerId = ca.ComputerId, Status = ca.Status, StartedAt = ca.StartedAt, FinishedAt = ca.FinishedAt, Score = ca.Score, CheckResults = ca.CheckResults })
                .FirstOrDefaultAsync(ct);
        }
        return BuildComputerAuditPdf(audit, previous, await ScoreThresholds.LoadAsync(_db, ct), generatedBy, generatedAtUtc);
    }

    // Pure builders are intentionally public for unit tests and do not require a logo file.
    public byte[] BuildAuditRunPdf(AuditRun run, ScoreThresholds thresholds, string generatedBy, DateTime generatedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(run);
        return Document.Create(doc => doc.Page(page =>
        {
            ConfigurePage(page, generatedBy, generatedAtUtc);
            page.Content().PaddingVertical(8).Column(col =>
            {
                col.Spacing(10);
                col.Item().Text($"Audit Run #{run.Id}").FontSize(18).Bold().FontColor(Navy);
                var average = AuditAnalyticsService.ComputeAverageScore(run.ComputerAudits.Select(a => a.Score));
                col.Item().Text($"Started by: {run.StartedByName}   |   Run date: {AuditAnalyticsService.FormatLocalDateTime(run.CreatedAt)}   |   Computers audited: {run.ComputerAudits.Count}   |   Average score: {(average?.ToString() ?? "N/A")} ({thresholds.Describe(average).Label})");
                col.Item().Text("Risk summary: " + string.Join("  ", new[] { "Secure", "Low", "Medium", "High", "Critical" }.Select(x => $"{x}: {RiskCount(run.ComputerAudits, x)}"))).FontSize(9);
                col.Item().Element(c => ComputerSummaryTable(c, run.ComputerAudits));
                foreach (var audit in run.ComputerAudits.OrderBy(a => a.Computer?.Name, StringComparer.OrdinalIgnoreCase))
                    col.Item().Element(c => FailedSection(c, audit));
            });
        })).GeneratePdf();
    }

    public byte[] BuildComputerAuditPdf(ComputerAudit audit, ComputerAudit? previous, ScoreThresholds thresholds, string generatedBy, DateTime generatedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(audit);
        return Document.Create(doc => doc.Page(page =>
        {
            ConfigurePage(page, generatedBy, generatedAtUtc);
            page.Content().PaddingVertical(8).Column(col =>
            {
                col.Spacing(8);
                col.Item().Text($"Computer Audit — {audit.Computer?.Name ?? "Unknown computer"}").FontSize(18).Bold().FontColor(Navy);
                col.Item().Text($"Host: {audit.Computer?.HostName ?? "—"}   |   Location: {audit.Computer?.Location ?? "—"}   |   Audited: {FormatAuditTime(audit)}");
                col.Item().Text($"OS: {audit.OsCaption ?? "—"} {audit.OsVersion ?? ""}   |   PowerShell: {audit.PsVersion ?? "—"}   |   Score: {audit.Score?.ToString() ?? "N/A"} ({thresholds.Describe(audit.Score).Label})   |   Risk: {AuditAnalyticsService.DescribeComputerAuditRisk(audit.Status, audit.OverallRisk, audit.Score).Label}");
                col.Item().Element(c => FailedSection(c, audit));
                col.Item().Text("Other check results").FontSize(14).Bold().FontColor(Navy);
                foreach (var group in AuditAnalyticsService.GroupResultsByCategory(audit.CheckResults.Where(r => r.Status != CheckStatus.Fail)))
                {
                    col.Item().Text(group.DisplayName).Bold();
                    col.Item().Element(c => SimpleChecksTable(c, group.Results));
                }
                col.Item().Element(c => Comparison(c, audit, previous));
            });
        })).GeneratePdf();
    }

    public byte[] BuildAuditRunCsv(AuditRun run)
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[] { 0xEF, 0xBB, 0xBF });
        using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true);
        using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
        csv.WriteHeader<CsvRow>(); csv.NextRecord();
        foreach (var audit in run.ComputerAudits)
        {
            var risk = AuditAnalyticsService.DescribeComputerAuditRisk(audit.Status, audit.OverallRisk, audit.Score).Label;
            if (!audit.CheckResults.Any())
            {
                Write(csv, run.Id, audit, risk, null, audit.Status.ToDisplayName(), audit.ErrorMessage, null);
                continue;
            }
            foreach (var check in audit.CheckResults)
                Write(csv, run.Id, audit, risk, check, check.Status.ToString(), check.ActualValue, check.ExpectedValue);
        }
        writer.Flush();
        return stream.ToArray();
    }

    public static string BuildRunFileName(int id, DateTime date) => $"SecureCheck_Run{id}_{date:yyyyMMdd}";
    public static string BuildComputerFileName(string name, DateTime date)
    {
        var safe = string.Concat((name ?? "Computer").Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        return $"SecureCheck_{safe}_{date:yyyyMMdd}";
    }

    private async Task<AuditRun?> LoadRunAsync(int id, CancellationToken ct) => await _db.AuditRuns.AsNoTracking().Where(r => r.Id == id)
        .Select(r => new AuditRun { Id = r.Id, StartedByName = r.StartedByName, CreatedAt = r.CreatedAt, StartedAt = r.StartedAt, FinishedAt = r.FinishedAt, Status = r.Status, TotalComputers = r.TotalComputers, CompletedComputers = r.CompletedComputers,
            ComputerAudits = r.ComputerAudits.Select(a => new ComputerAudit { Id = a.Id, AuditRunId = a.AuditRunId, ComputerId = a.ComputerId, Computer = a.Computer, Status = a.Status, StartedAt = a.StartedAt, FinishedAt = a.FinishedAt, Score = a.Score, OverallRisk = a.OverallRisk, PassedCount = a.PassedCount, FailedCount = a.FailedCount, ErrorCount = a.ErrorCount, ErrorMessage = a.ErrorMessage, OsCaption = a.OsCaption, OsVersion = a.OsVersion, PsVersion = a.PsVersion, CheckResults = a.CheckResults }).ToList() }).FirstOrDefaultAsync(ct);
    private async Task<ComputerAudit?> LoadComputerAuditAsync(int id, CancellationToken ct) => await _db.ComputerAudits.AsNoTracking().Where(a => a.Id == id).Select(a => new ComputerAudit { Id = a.Id, AuditRunId = a.AuditRunId, AuditRun = a.AuditRun, ComputerId = a.ComputerId, Computer = a.Computer, Status = a.Status, StartedAt = a.StartedAt, FinishedAt = a.FinishedAt, Score = a.Score, OverallRisk = a.OverallRisk, PassedCount = a.PassedCount, FailedCount = a.FailedCount, ErrorCount = a.ErrorCount, ErrorMessage = a.ErrorMessage, OsCaption = a.OsCaption, OsVersion = a.OsVersion, PsVersion = a.PsVersion, CheckResults = a.CheckResults }).FirstOrDefaultAsync(ct);
    private void ConfigurePage(PageDescriptor page, string user, DateTime at)
    {
        page.Size(PageSizes.A4); page.Margin(32); page.DefaultTextStyle(x => x.FontSize(9));
        page.Header().Row(row => { var logo = TryGetLogo(); if (logo is not null) row.ConstantItem(42).Height(28).Image(logo).FitArea(); row.RelativeItem().Column(c => { c.Item().Text("SecureCheck — Endpoint Security Audit Report").Bold().FontColor(Navy); c.Item().Text($"Generated {AuditAnalyticsService.FormatLocalDateTime(at)} by {user}").FontSize(8); }); });
        page.Footer().AlignCenter().Text(t => { t.Span("Page "); t.CurrentPageNumber(); t.Span(" of "); t.TotalPages(); });
    }
    private byte[]? TryGetLogo() { var p = Path.Combine(_environment.WebRootPath ?? "", "img", "logo.png"); return File.Exists(p) ? File.ReadAllBytes(p) : null; }
    private static void ComputerSummaryTable(IContainer c, IEnumerable<ComputerAudit> audits) => c.Table(t => { t.ColumnsDefinition(x => { x.RelativeColumn(2); x.RelativeColumn(); x.ConstantColumn(40); x.RelativeColumn(); x.ConstantColumn(45); x.RelativeColumn(); }); Header(t, "Name", "Location", "Score", "Risk", "Failed", "Status"); foreach (var a in audits) Row(t, a.Computer?.Name, a.Computer?.Location, a.Score?.ToString() ?? "—", AuditAnalyticsService.DescribeComputerAuditRisk(a.Status,a.OverallRisk,a.Score).Label, a.FailedCount.ToString(), a.Status.ToDisplayName()); });
    private static void FailedSection(IContainer c, ComputerAudit a) { c.Column(col => { col.Spacing(4); col.Item().Text($"{a.Computer?.Name ?? "Computer"} — failed checks").FontSize(13).Bold().FontColor(Navy); if (a.Status is ComputerAuditStatus.Unreachable or ComputerAuditStatus.Failed) col.Item().Text(a.ErrorMessage ?? a.Status.ToDisplayName()).FontColor(Gray); else { var failed=AuditAnalyticsService.OrderFailedChecksWorstFirst(a.CheckResults); if (!failed.Any()) col.Item().Text("No failed checks.").FontColor(Green); else col.Item().Table(t => { t.ColumnsDefinition(x=>{x.RelativeColumn(2);x.RelativeColumn();x.RelativeColumn();x.RelativeColumn();x.RelativeColumn(3);}); Header(t,"Check","Risk","Actual","Expected","How to fix"); foreach(var r in failed) Row(t, $"{r.Code} — {r.Name}",r.RiskLevel.ToString(),r.ActualValue,r.ExpectedValue,r.Remediation); }); } }); }
    private static void SimpleChecksTable(IContainer c, IEnumerable<CheckResult> rows) => c.Table(t => { t.ColumnsDefinition(x=>{x.RelativeColumn(2);x.RelativeColumn();x.RelativeColumn(2);}); Header(t,"Check","Status","Details"); foreach(var r in rows) Row(t,$"{r.Code} — {r.Name}",r.Status.ToString(),r.Message); });
    private static void Comparison(IContainer c, ComputerAudit current, ComputerAudit? previous) { c.Column(col => { col.Item().Text("Comparison with previous completed audit").FontSize(14).Bold().FontColor(Navy); if(previous is null) col.Item().Text("No earlier completed audit exists."); else { var x=AuditAnalyticsService.CompareAudits(current,previous); col.Item().Text($"Score delta: {x.ScoreDeltaDisplay}; Newly failing: {x.NewlyFailing.Count}; Fixed since last audit: {x.FixedSinceLastAudit.Count}; Still failing: {x.StillFailing.Count}"); } }); }
    private static void Header(TableDescriptor t, params string[] cells) => t.Header(header => { foreach (var cell in cells) header.Cell().Background(Navy).Padding(3).Text(cell).FontColor(Colors.White).Bold(); });
    private static void Row(TableDescriptor t, params string?[] cells) { foreach(var x in cells) t.Cell().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(3).Text(x ?? "—"); }
    private static int RiskCount(IEnumerable<ComputerAudit> a, string risk) => a.Count(x => AuditAnalyticsService.DescribeComputerAuditRisk(x.Status,x.OverallRisk,x.Score).Label == risk);
    private static string FormatAuditTime(ComputerAudit a) => a.FinishedAt.HasValue ? AuditAnalyticsService.FormatLocalDateTime(a.FinishedAt.Value) : "—";
    private static void Write(CsvWriter c, int runId, ComputerAudit a, string risk, CheckResult? r, string status, string? actual, string? expected) { c.WriteRecord(new CsvRow { RunId=runId, ComputerName=Safe(a.Computer?.Name), HostName=Safe(a.Computer?.HostName), Location=Safe(a.Computer?.Location), AuditedAt=FormatAuditTime(a), ComputerScore=a.Score, ComputerOverallRisk=risk, CheckCode=Safe(r?.Code), CheckName=Safe(r?.Name), Category=r?.Category.ToDisplayName(), RiskLevel=r?.RiskLevel.ToString(), Status=status, ActualValue=Safe(actual), ExpectedValue=Safe(expected) }); c.NextRecord(); }
    private static string? Safe(string? value) => !string.IsNullOrEmpty(value) && "=+-@".Contains(value[0]) ? "'" + value : value;
    private sealed class CsvRow { public int RunId {get;set;} public string? ComputerName {get;set;} public string? HostName {get;set;} public string? Location {get;set;} public string? AuditedAt {get;set;} public int? ComputerScore {get;set;} public string? ComputerOverallRisk {get;set;} public string? CheckCode {get;set;} public string? CheckName {get;set;} public string? Category {get;set;} public string? RiskLevel {get;set;} public string? Status {get;set;} public string? ActualValue {get;set;} public string? ExpectedValue {get;set;} }
}
