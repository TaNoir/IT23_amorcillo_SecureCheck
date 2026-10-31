using System.ComponentModel.DataAnnotations;

namespace SecureCheck.Web.Models;

/// <summary>
/// Key-value application configuration stored in the database.
/// </summary>
public class AppSetting
{
    [Key, MaxLength(100)]
    public string Key { get; set; } = string.Empty;

    [MaxLength(2000)]
    public string Value { get; set; } = string.Empty;
}

/// <summary>Well-known AppSetting keys defined in PROJECT_BRIEF.</summary>
public static class AppSettingKeys
{
    public const string DefaultCredentialUserName = "DefaultCredentialUserName";
    public const string DefaultCredentialPasswordProtected = "DefaultCredentialPasswordProtected";
    public const string MaxParallelAudits = "MaxParallelAudits";
    public const string AuditTimeoutSeconds = "AuditTimeoutSeconds";
    public const string ScoreGoodMin = "ScoreGoodMin";
    public const string ScoreFairMin = "ScoreFairMin";
    public const string ScorePoorMin = "ScorePoorMin";
}

