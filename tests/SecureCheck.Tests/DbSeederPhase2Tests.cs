using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Tests;

public class DbSeederPhase2Tests
{
    [Fact]
    public void Default_checklist_contains_all_16_unique_checks_from_brief()
    {
        var checks = DbSeeder.GetDefaultChecks();

        Assert.Equal(16, checks.Count);
        Assert.Equal(16, checks.Select(c => c.Code).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(checks, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Code));
            Assert.False(string.IsNullOrWhiteSpace(c.Name));
            Assert.False(string.IsNullOrWhiteSpace(c.Remediation));
            Assert.True(c.IsEnabled);
        });
    }

    [Theory]
    [InlineData("FW-DOMAIN", CheckCategory.Firewall, RiskLevel.High, null)]
    [InlineData("FW-PRIVATE", CheckCategory.Firewall, RiskLevel.High, null)]
    [InlineData("FW-PUBLIC", CheckCategory.Firewall, RiskLevel.Critical, null)]
    [InlineData("UPD-RECENT", CheckCategory.Updates, RiskLevel.High, 30)]
    [InlineData("AV-ENABLED", CheckCategory.Antivirus, RiskLevel.Critical, null)]
    [InlineData("AV-REALTIME", CheckCategory.Antivirus, RiskLevel.High, null)]
    [InlineData("AV-SIGNATURES", CheckCategory.Antivirus, RiskLevel.Medium, 7)]
    [InlineData("ACC-GUEST", CheckCategory.Accounts, RiskLevel.High, null)]
    [InlineData("ACC-ADMINS", CheckCategory.Accounts, RiskLevel.Medium, 2)]
    [InlineData("ACC-PWLENGTH", CheckCategory.Accounts, RiskLevel.Medium, 8)]
    [InlineData("ACC-PWCOMPLEX", CheckCategory.Accounts, RiskLevel.Medium, null)]
    [InlineData("ACC-LOCKOUT", CheckCategory.Accounts, RiskLevel.Medium, 10)]
    [InlineData("SVC-REMOTEREG", CheckCategory.ServicesAndFeatures, RiskLevel.Medium, null)]
    [InlineData("SVC-RDP", CheckCategory.ServicesAndFeatures, RiskLevel.Medium, null)]
    [InlineData("SVC-SMB1", CheckCategory.ServicesAndFeatures, RiskLevel.Critical, null)]
    [InlineData("SVC-TELNET", CheckCategory.ServicesAndFeatures, RiskLevel.Low, null)]
    public void Each_seeded_check_matches_brief_category_risk_and_threshold(
        string code,
        CheckCategory expectedCategory,
        RiskLevel expectedRisk,
        int? expectedThreshold)
    {
        var check = Assert.Single(DbSeeder.GetDefaultChecks(), c => c.Code == code);

        Assert.Equal(expectedCategory, check.Category);
        Assert.Equal(expectedRisk, check.RiskLevel);
        Assert.Equal(expectedThreshold, check.Threshold);

        if (expectedThreshold.HasValue)
            Assert.False(string.IsNullOrWhiteSpace(check.ThresholdLabel));
        else
            Assert.Null(check.ThresholdLabel);
    }

    [Fact]
    public void RiskLevel_enum_values_match_scoring_weights()
    {
        Assert.Equal(1, (int)RiskLevel.Low);
        Assert.Equal(2, (int)RiskLevel.Medium);
        Assert.Equal(3, (int)RiskLevel.High);
        Assert.Equal(4, (int)RiskLevel.Critical);
    }

    [Fact]
    public void Default_AppSettings_contain_all_brief_keys_and_defaults()
    {
        var settings = DbSeeder.GetDefaultSettings().ToDictionary(s => s.Key, s => s.Value);

        Assert.Equal(7, settings.Count);
        Assert.Equal(string.Empty, settings[AppSettingKeys.DefaultCredentialUserName]);
        Assert.Equal(string.Empty, settings[AppSettingKeys.DefaultCredentialPasswordProtected]);
        Assert.Equal("5", settings[AppSettingKeys.MaxParallelAudits]);
        Assert.Equal("180", settings[AppSettingKeys.AuditTimeoutSeconds]);
        Assert.Equal("90", settings[AppSettingKeys.ScoreGoodMin]);
        Assert.Equal("70", settings[AppSettingKeys.ScoreFairMin]);
        Assert.Equal("50", settings[AppSettingKeys.ScorePoorMin]);
    }
}

