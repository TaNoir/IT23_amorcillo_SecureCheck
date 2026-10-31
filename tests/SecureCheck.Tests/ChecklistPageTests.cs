using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;
using ChecklistIndexModel = SecureCheck.Web.Pages.Admin.Checklist.IndexModel;

namespace SecureCheck.Tests;

public class ChecklistPageTests
{
    private static ApplicationDbContext CreateContext()
    {
        // No connection is opened; used only to generate SQL text.
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlServer("Server=.;Database=SecureCheckModelInspection;Trusted_Connection=True")
            .Options;
        return new ApplicationDbContext(options);
    }

    [Fact]
    public void Display_order_SQL_sorts_by_SortOrder_not_the_string_Category_column()
    {
        using var db = CreateContext();

        var sql = ChecklistIndexModel.ApplyDisplayOrder(db.CheckDefinitions).ToQueryString();
        var orderBy = sql[sql.IndexOf("ORDER BY", StringComparison.Ordinal)..];

        Assert.StartsWith("ORDER BY [c].[SortOrder]", orderBy);
        Assert.DoesNotContain("[Category]", orderBy);
    }

    [Fact]
    public void Seeded_SortOrder_groups_categories_in_brief_order()
    {
        var categories = ChecklistIndexModel
            .ApplyDisplayOrder(DbSeeder.GetDefaultChecks().AsQueryable())
            .Select(c => c.Category)
            .ToList();

        // The page renders one card per run of the same category, so each category must be contiguous.
        var groups = categories
            .Where((c, i) => i == 0 || categories[i - 1] != c)
            .ToList();

        Assert.Equal(
            new[]
            {
                CheckCategory.Firewall,
                CheckCategory.Updates,
                CheckCategory.Antivirus,
                CheckCategory.Accounts,
                CheckCategory.ServicesAndFeatures
            },
            groups);
    }
}

