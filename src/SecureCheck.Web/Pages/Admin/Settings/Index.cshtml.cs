using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Web.Pages.Admin.Settings;

[Authorize(Policy = AppPolicies.Manage)]
public class IndexModel : PageModel
{
    private readonly ApplicationDbContext _db;
    private readonly CredentialProtector _protector;
    private readonly ActivityLogService _activityLog;

    public IndexModel(
        ApplicationDbContext db,
        CredentialProtector protector,
        ActivityLogService activityLog)
    {
        _db = db;
        _protector = protector;
        _activityLog = activityLog;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool HasStoredDefaultPassword { get; private set; }

    [TempData]
    public string? StatusMessage { get; set; }

    public class InputModel
    {
        [MaxLength(150)]
        [Display(Name = "Default Credential Username")]
        public string? DefaultCredentialUserName { get; set; }

        [DataType(DataType.Password), MaxLength(200)]
        [Display(Name = "Default Credential Password")]
        public string? DefaultCredentialPassword { get; set; }

        [Display(Name = "Clear saved default credential")]
        public bool ClearDefaultCredential { get; set; }

        [Range(1, 20, ErrorMessage = "Max parallel audits must be between 1 and 20.")]
        [Display(Name = "Max Parallel Audits (1–20)")]
        public int MaxParallelAudits { get; set; } = 5;

        [Range(30, 600, ErrorMessage = "Audit timeout must be between 30 and 600 seconds.")]
        [Display(Name = "Audit Timeout Seconds (30–600)")]
        public int AuditTimeoutSeconds { get; set; } = 180;

        [Range(1, 100, ErrorMessage = "Good threshold must be between 1 and 100.")]
        [Display(Name = "Good Score Minimum")]
        public int ScoreGoodMin { get; set; } = 90;

        [Range(1, 100, ErrorMessage = "Fair threshold must be between 1 and 100.")]
        [Display(Name = "Fair Score Minimum")]
        public int ScoreFairMin { get; set; } = 70;

        [Range(1, 100, ErrorMessage = "Poor threshold must be between 1 and 100.")]
        [Display(Name = "Poor Score Minimum")]
        public int ScorePoorMin { get; set; } = 50;
    }

    public async Task OnGetAsync()
    {
        var map = await LoadSettingsMapAsync();
        HasStoredDefaultPassword = !string.IsNullOrEmpty(GetValue(map, AppSettingKeys.DefaultCredentialPasswordProtected, string.Empty));

        Input = new InputModel
        {
            DefaultCredentialUserName = GetValue(map, AppSettingKeys.DefaultCredentialUserName, string.Empty),
            MaxParallelAudits = GetInt(map, AppSettingKeys.MaxParallelAudits, 5),
            AuditTimeoutSeconds = GetInt(map, AppSettingKeys.AuditTimeoutSeconds, 180),
            ScoreGoodMin = GetInt(map, AppSettingKeys.ScoreGoodMin, 90),
            ScoreFairMin = GetInt(map, AppSettingKeys.ScoreFairMin, 70),
            ScorePoorMin = GetInt(map, AppSettingKeys.ScorePoorMin, 50)
        };
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var existingRows = await _db.AppSettings.ToDictionaryAsync(s => s.Key, StringComparer.OrdinalIgnoreCase);
        var existingProtectedPass = existingRows.TryGetValue(AppSettingKeys.DefaultCredentialPasswordProtected, out var pwRow)
            ? pwRow.Value
            : string.Empty;
        HasStoredDefaultPassword = !string.IsNullOrEmpty(existingProtectedPass);

        var credUser = string.IsNullOrWhiteSpace(Input.DefaultCredentialUserName)
            ? string.Empty
            : Input.DefaultCredentialUserName.Trim();
        var credPass = Input.DefaultCredentialPassword;

        // Never echo a submitted password back into the HTML form.
        Input.DefaultCredentialPassword = null;

        if (!Input.ClearDefaultCredential)
        {
            if (string.IsNullOrEmpty(credUser) && !string.IsNullOrEmpty(credPass))
            {
                ModelState.AddModelError("Input.DefaultCredentialUserName", "Enter a username for the default audit credential.");
            }
            else if (!string.IsNullOrEmpty(credUser) && string.IsNullOrEmpty(credPass) && !HasStoredDefaultPassword)
            {
                ModelState.AddModelError("Input.DefaultCredentialPassword", "Enter a password when setting the default credential for the first time.");
            }
        }

        if (!(Input.ScoreGoodMin > Input.ScoreFairMin && Input.ScoreFairMin > Input.ScorePoorMin))
        {
            ModelState.AddModelError(string.Empty, "Score label thresholds must be strictly descending: Good > Fair > Poor.");
        }

        if (!ModelState.IsValid)
            return Page();

        string newUserValue;
        string newProtectedPassValue;
        string credLogNote;

        if (Input.ClearDefaultCredential || string.IsNullOrEmpty(credUser))
        {
            newUserValue = string.Empty;
            newProtectedPassValue = string.Empty;
            credLogNote = "cleared";
        }
        else if (!string.IsNullOrEmpty(credPass))
        {
            newUserValue = credUser;
            newProtectedPassValue = _protector.Protect(credPass);
            credLogNote = $"username={credUser} (password updated)";
        }
        else
        {
            newUserValue = credUser;
            newProtectedPassValue = existingProtectedPass;
            credLogNote = $"username={credUser} (password unchanged)";
        }

        Upsert(existingRows, AppSettingKeys.DefaultCredentialUserName, newUserValue);
        Upsert(existingRows, AppSettingKeys.DefaultCredentialPasswordProtected, newProtectedPassValue);
        Upsert(existingRows, AppSettingKeys.MaxParallelAudits, Input.MaxParallelAudits.ToString());
        Upsert(existingRows, AppSettingKeys.AuditTimeoutSeconds, Input.AuditTimeoutSeconds.ToString());
        Upsert(existingRows, AppSettingKeys.ScoreGoodMin, Input.ScoreGoodMin.ToString());
        Upsert(existingRows, AppSettingKeys.ScoreFairMin, Input.ScoreFairMin.ToString());
        Upsert(existingRows, AppSettingKeys.ScorePoorMin, Input.ScorePoorMin.ToString());

        await _db.SaveChangesAsync();

        await _activityLog.LogAsync(
            User.Identity?.Name,
            "Updated Settings",
            $"DefaultCredential: {credLogNote}; MaxParallelAudits={Input.MaxParallelAudits}; AuditTimeoutSeconds={Input.AuditTimeoutSeconds}; Scores(Good>={Input.ScoreGoodMin}, Fair>={Input.ScoreFairMin}, Poor>={Input.ScorePoorMin})");

        StatusMessage = "Application settings saved.";
        return RedirectToPage();
    }

    private void Upsert(Dictionary<string, AppSetting> existing, string key, string value)
    {
        if (existing.TryGetValue(key, out var row))
        {
            row.Value = value;
        }
        else
        {
            var created = new AppSetting { Key = key, Value = value };
            _db.AppSettings.Add(created);
            existing[key] = created;
        }
    }

    private Task<Dictionary<string, string>> LoadSettingsMapAsync() =>
        _db.AppSettings
            .AsNoTracking()
            .ToDictionaryAsync(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase);

    private static string GetValue(Dictionary<string, string> map, string key, string fallback) =>
        map.TryGetValue(key, out var val) ? val : fallback;

    private static int GetInt(Dictionary<string, string> map, string key, int fallback) =>
        map.TryGetValue(key, out var val) && int.TryParse(val, out var parsed) ? parsed : fallback;
}

