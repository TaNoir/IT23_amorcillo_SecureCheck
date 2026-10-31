using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Web.Services;

/// <summary>
/// Records administrative and operational events to the ActivityLogs table.
/// Callers must never pass plain or encrypted passwords in action or details.
/// </summary>
public class ActivityLogService
{
    private readonly ApplicationDbContext _db;

    public ActivityLogService(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task LogAsync(string? userName, string action, string? details = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);

        var entry = new ActivityLog
        {
            UserName = string.IsNullOrWhiteSpace(userName) ? "System" : userName.Trim(),
            Action = action.Trim(),
            Details = string.IsNullOrWhiteSpace(details) ? null : details.Trim(),
            CreatedAt = DateTime.UtcNow
        };

        _db.ActivityLogs.Add(entry);
        await _db.SaveChangesAsync();
    }
}

