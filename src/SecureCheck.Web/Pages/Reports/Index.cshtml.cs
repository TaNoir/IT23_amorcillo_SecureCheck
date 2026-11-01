using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Reports;

/// <summary>Authenticated report exports. FallbackPolicy intentionally permits every signed-in role.</summary>
public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly ReportService _reports;
    private readonly ActivityLogService _activity;
    public IndexModel(ApplicationDbContext db, ReportService reports, ActivityLogService activity) => (_db, _reports, _activity) = (db, reports, activity);
    public IReadOnlyList<ReportRunRow> Runs { get; private set; } = Array.Empty<ReportRunRow>();

    public async Task OnGetAsync(CancellationToken ct) => Runs = await _db.AuditRuns.AsNoTracking().OrderByDescending(r => r.CreatedAt)
        .Select(r => new ReportRunRow(r.Id, r.CreatedAt, r.StartedByName, r.Status.ToString(), r.TotalComputers, r.CompletedComputers)).ToListAsync(ct);
    public async Task<IActionResult> OnGetRunPdfAsync(int runId, CancellationToken ct) => await ExportRun(runId, true, ct);
    public async Task<IActionResult> OnGetRunCsvAsync(int runId, CancellationToken ct) => await ExportRun(runId, false, ct);
    public async Task<IActionResult> OnGetComputerPdfAsync(int computerAuditId, CancellationToken ct)
    {
        var bytes = await _reports.BuildComputerAuditPdfAsync(computerAuditId, User.GetFullName(), DateTime.UtcNow, ct);
        if (bytes is null) return NotFound();
        var name = await _db.ComputerAudits.Where(x => x.Id == computerAuditId).Select(x => x.Computer.Name).FirstAsync(ct);
        await _activity.LogAsync(User.GetFullName(), "Exported computer audit PDF", $"Computer audit #{computerAuditId}");
        return File(bytes, "application/pdf", ReportService.BuildComputerFileName(name, DateTime.Now) + ".pdf");
    }
    private async Task<IActionResult> ExportRun(int id, bool pdf, CancellationToken ct)
    {
        var bytes = pdf ? await _reports.BuildAuditRunPdfAsync(id, User.GetFullName(), DateTime.UtcNow, ct) : await _reports.BuildAuditRunCsvAsync(id, ct);
        if (bytes is null) return NotFound();
        await _activity.LogAsync(User.GetFullName(), pdf ? "Exported audit run PDF" : "Exported audit run CSV", $"Audit run #{id}");
        return File(bytes, pdf ? "application/pdf" : "text/csv", ReportService.BuildRunFileName(id, DateTime.Now) + (pdf ? ".pdf" : ".csv"));
    }
    public sealed record ReportRunRow(int Id, DateTime CreatedAt, string StartedByName, string Status, int TotalComputers, int CompletedComputers);
}
