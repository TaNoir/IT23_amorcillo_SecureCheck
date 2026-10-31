using Microsoft.EntityFrameworkCore;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Tests;

public class ApplicationDbContextModelTests
{
    private static ApplicationDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlServer("Server=.;Database=SecureCheckModelInspection;Trusted_Connection=True")
            .Options;
        return new ApplicationDbContext(options);
    }

    [Fact]
    public void Unique_indexes_are_configured_on_Computer_Name_and_CheckDefinition_Code()
    {
        using var db = CreateContext();

        var computerEntity = db.Model.FindEntityType(typeof(Computer))!;
        var nameIndex = computerEntity.GetIndexes()
            .SingleOrDefault(ix => ix.Properties.Select(p => p.Name).SequenceEqual(new[] { nameof(Computer.Name) }));
        Assert.NotNull(nameIndex);
        Assert.True(nameIndex!.IsUnique);

        var checkEntity = db.Model.FindEntityType(typeof(CheckDefinition))!;
        var codeIndex = checkEntity.GetIndexes()
            .SingleOrDefault(ix => ix.Properties.Select(p => p.Name).SequenceEqual(new[] { nameof(CheckDefinition.Code) }));
        Assert.NotNull(codeIndex);
        Assert.True(codeIndex!.IsUnique);
    }

    [Theory]
    [InlineData(typeof(Computer), nameof(Computer.LastRiskLevel))]
    [InlineData(typeof(CheckDefinition), nameof(CheckDefinition.Category))]
    [InlineData(typeof(CheckDefinition), nameof(CheckDefinition.RiskLevel))]
    [InlineData(typeof(AuditRun), nameof(AuditRun.Status))]
    [InlineData(typeof(ComputerAudit), nameof(ComputerAudit.Status))]
    [InlineData(typeof(ComputerAudit), nameof(ComputerAudit.OverallRisk))]
    [InlineData(typeof(CheckResult), nameof(CheckResult.Category))]
    [InlineData(typeof(CheckResult), nameof(CheckResult.RiskLevel))]
    [InlineData(typeof(CheckResult), nameof(CheckResult.Status))]
    [InlineData(typeof(Alert), nameof(Alert.Severity))]
    public void All_enum_properties_are_stored_as_strings(Type entityClrType, string propertyName)
    {
        using var db = CreateContext();

        var entity = db.Model.FindEntityType(entityClrType)!;
        var property = entity.FindProperty(propertyName)!;

        Assert.Equal(typeof(string), property.GetProviderClrType());
        Assert.StartsWith("nvarchar", property.GetColumnType(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Delete_behaviors_cascade_on_AuditRun_and_restrict_on_Computer()
    {
        using var db = CreateContext();

        var computerAuditEntity = db.Model.FindEntityType(typeof(ComputerAudit))!;
        var auditRunFk = computerAuditEntity.GetForeignKeys()
            .Single(fk => fk.PrincipalEntityType.ClrType == typeof(AuditRun));
        var computerFk = computerAuditEntity.GetForeignKeys()
            .Single(fk => fk.PrincipalEntityType.ClrType == typeof(Computer));

        Assert.Equal(DeleteBehavior.Cascade, auditRunFk.DeleteBehavior);
        Assert.Equal(DeleteBehavior.Restrict, computerFk.DeleteBehavior);

        var checkResultEntity = db.Model.FindEntityType(typeof(CheckResult))!;
        var computerAuditFk = checkResultEntity.GetForeignKeys()
            .Single(fk => fk.PrincipalEntityType.ClrType == typeof(ComputerAudit));
        Assert.Equal(DeleteBehavior.Cascade, computerAuditFk.DeleteBehavior);
    }
}
