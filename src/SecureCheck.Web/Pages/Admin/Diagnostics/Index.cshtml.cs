using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Admin.Diagnostics;

[Authorize(Policy = AppPolicies.Manage)]
public class IndexModel : PageModel
{
    private static readonly JsonSerializerOptions IndentedJsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly ApplicationDbContext _db;
    private readonly PowerShellRunner _runner;
    private readonly ActivityLogService _activityLog;

    public IndexModel(
        ApplicationDbContext db,
        PowerShellRunner runner,
        ActivityLogService activityLog)
    {
        _db = db;
        _runner = runner;
        _activityLog = activityLog;
    }

    public IReadOnlyList<Computer> Computers { get; private set; } = Array.Empty<Computer>();

    [BindProperty]
    public int? SelectedComputerId { get; set; }

    public Computer? ExecutedComputer { get; private set; }
    public ExecutionMode? ExecutedMode { get; private set; }
    public TimeSpan? Duration { get; private set; }
    public string? PrettyJson { get; private set; }
    public RunnerErrorKind? ErrorKind { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync(int? computerId = null)
    {
        await LoadComputersAsync();
        SelectedComputerId = computerId ?? Computers.FirstOrDefault()?.Id;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        await LoadComputersAsync();

        if (!SelectedComputerId.HasValue)
        {
            ErrorMessage = "Select a computer before running the audit script.";
            return Page();
        }

        var computer = Computers.FirstOrDefault(c => c.Id == SelectedComputerId.Value);
        if (computer is null)
        {
            ErrorMessage = "The selected computer could not be found.";
            return Page();
        }

        ExecutedComputer = computer;
        ExecutedMode = PowerShellRunner.DetermineMode(computer.HostName);

        var result = await _runner.RunAuditAsync(computer, HttpContext.RequestAborted);
        Duration = result.Duration;

        if (result.Success && !string.IsNullOrWhiteSpace(result.Json))
        {
            PrettyJson = FormatJsonPretty(result.Json);
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Ran Diagnostics Script",
                $"{computer.Name} ({computer.HostName}): Succeeded in {result.Duration.TotalSeconds:F2}s");
        }
        else
        {
            ErrorKind = result.ErrorKind;
            ErrorMessage = result.ErrorMessage ?? "Audit script execution failed.";
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Ran Diagnostics Script",
                $"{computer.Name} ({computer.HostName}): Failed ({result.ErrorKind}) — {ErrorMessage}");
        }

        return Page();
    }

    public static string FormatJsonPretty(string rawJson)
    {
        if (string.IsNullOrWhiteSpace(rawJson))
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            return JsonSerializer.Serialize(doc.RootElement, IndentedJsonOptions);
        }
        catch (JsonException)
        {
            return rawJson;
        }
    }

    private async Task LoadComputersAsync()
    {
        Computers = await _db.Computers
            .AsNoTracking()
            .OrderByDescending(c => c.IsActive)
            .ThenBy(c => c.Name)
            .ToListAsync();
    }
}

