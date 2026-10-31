using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Admin.Checklist;

[Authorize(Policy = AppPolicies.Manage)]
public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly ActivityLogService _activityLog;

    public IndexModel(
        ApplicationDbContext db,
        ActivityLogService activityLog)
    {
        _db = db;
        _activityLog = activityLog;
    }

    [BindProperty]
    public List<CheckItemInput> Items { get; set; } = new();

    [TempData]
    public string? StatusMessage { get; set; }

    public class CheckItemInput
    {
        public int Id { get; set; }

        // Read-only display properties populated from the database:
        public string Code { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public CheckCategory Category { get; set; }
        public string Description { get; set; } = string.Empty;
        public string? ThresholdLabel { get; set; }

        // Editable properties:
        public RiskLevel RiskLevel { get; set; }

        [Range(1, 3650, ErrorMessage = "Threshold must be between 1 and 3,650.")]
        public int? Threshold { get; set; }

        [Required(ErrorMessage = "Remediation guidance is required.")]
        [MaxLength(2000)]
        public string Remediation { get; set; } = string.Empty;

        public bool IsEnabled { get; set; }
    }

    public async Task OnGetAsync()
    {
        var checks = await LoadOrderedChecksAsync();
        Items = checks.Select(MapToInput).ToList();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var dbChecks = await LoadOrderedChecksAsync();
        var dbById = dbChecks.ToDictionary(c => c.Id);

        if (Items.Count == 0 || Items.Any(i => !dbById.ContainsKey(i.Id)))
        {
            ModelState.AddModelError(string.Empty, "Invalid checklist submission. Reloaded current checklist.");
            Items = dbChecks.Select(MapToInput).ToList();
            return Page();
        }

        // Re-populate read-only fields from DB and validate threshold rules before saving.
        for (var i = 0; i < Items.Count; i++)
        {
            var item = Items[i];
            if (!dbById.TryGetValue(item.Id, out var dbCheck))
                continue;

            item.Code = dbCheck.Code;
            item.Name = dbCheck.Name;
            item.Category = dbCheck.Category;
            item.Description = dbCheck.Description;
            item.ThresholdLabel = dbCheck.ThresholdLabel;

            if (!Enum.IsDefined(typeof(RiskLevel), item.RiskLevel))
            {
                ModelState.AddModelError($"Items[{i}].RiskLevel", "Select a valid risk level.");
            }

            if (dbCheck.ThresholdLabel is not null)
            {
                if (!item.Threshold.HasValue || item.Threshold.Value < 1)
                {
                    ModelState.AddModelError($"Items[{i}].Threshold", $"{dbCheck.Code} requires a positive threshold ({dbCheck.ThresholdLabel}).");
                }
            }
            else
            {
                // Checks without a threshold never store one.
                item.Threshold = null;
            }
        }

        if (!ModelState.IsValid)
            return Page();

        var updatedLogs = new List<(string Code, string Summary)>();

        foreach (var item in Items)
        {
            if (!dbById.TryGetValue(item.Id, out var dbCheck))
                continue;

            var changes = new List<string>();
            var trimmedRemediation = item.Remediation.Trim();

            if (dbCheck.RiskLevel != item.RiskLevel)
            {
                changes.Add($"Risk: {dbCheck.RiskLevel} -> {item.RiskLevel}");
                dbCheck.RiskLevel = item.RiskLevel;
            }

            if (dbCheck.ThresholdLabel is not null && dbCheck.Threshold != item.Threshold)
            {
                changes.Add($"Threshold: {dbCheck.Threshold} -> {item.Threshold}");
                dbCheck.Threshold = item.Threshold;
            }

            if (!string.Equals(dbCheck.Remediation, trimmedRemediation, StringComparison.Ordinal))
            {
                changes.Add("Remediation updated");
                dbCheck.Remediation = trimmedRemediation;
            }

            if (dbCheck.IsEnabled != item.IsEnabled)
            {
                changes.Add($"Enabled: {dbCheck.IsEnabled} -> {item.IsEnabled}");
                dbCheck.IsEnabled = item.IsEnabled;
            }

            if (changes.Count > 0)
            {
                updatedLogs.Add((dbCheck.Code, string.Join(", ", changes)));
            }
        }

        if (updatedLogs.Count == 0)
        {
            StatusMessage = "No checklist changes were made.";
            return RedirectToPage();
        }

        await _db.SaveChangesAsync();

        foreach (var (code, summary) in updatedLogs)
        {
            await _activityLog.LogAsync(
                User.Identity?.Name,
                "Updated Checklist Item",
                $"{code} ({summary})");
        }

        StatusMessage = $"Saved updates to {updatedLogs.Count} checklist {(updatedLogs.Count == 1 ? "item" : "items")}.";
        return RedirectToPage();
    }

    private Task<List<CheckDefinition>> LoadOrderedChecksAsync() =>
        _db.CheckDefinitions
            .OrderBy(c => c.Category)
            .ThenBy(c => c.SortOrder)
            .ThenBy(c => c.Code)
            .ToListAsync();

    private static CheckItemInput MapToInput(CheckDefinition c) => new()
    {
        Id = c.Id,
        Code = c.Code,
        Name = c.Name,
        Category = c.Category,
        Description = c.Description,
        ThresholdLabel = c.ThresholdLabel,
        RiskLevel = c.RiskLevel,
        Threshold = c.Threshold,
        Remediation = c.Remediation,
        IsEnabled = c.IsEnabled
    };
}
