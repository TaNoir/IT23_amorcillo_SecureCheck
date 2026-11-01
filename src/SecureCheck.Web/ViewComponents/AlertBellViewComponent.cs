using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;

namespace SecureCheck.Web.ViewComponents;

/// <summary>
/// Renders the top navbar bell icon and open alert count badge.
/// </summary>
public class AlertBellViewComponent : ViewComponent
{
    private readonly ApplicationDbContext _db;

    public AlertBellViewComponent(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<IViewComponentResult> InvokeAsync()
    {
        var openCount = await _db.Alerts
            .AsNoTracking()
            .CountAsync(a => !a.IsAcknowledged, HttpContext.RequestAborted);

        return View(openCount);
    }
}

