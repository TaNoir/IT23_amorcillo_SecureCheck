using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureCheck.Web.Models;

/// <summary>
/// C# representation of the schemaVersion 1 JSON payload emitted by Invoke-SecureCheckAudit.ps1.
/// All sections and fields are nullable so partial collection failures isolate to individual checks.
/// </summary>
public sealed class AuditFacts
{
    public const int SupportedSchemaVersion = 1;

    public static JsonSerializerOptions JsonOptions { get; } = CreateJsonOptions();

    public int? SchemaVersion { get; set; }
    public string? ComputerName { get; set; }
    public DateTimeOffset? CollectedAt { get; set; }
    public OsFacts? Os { get; set; }
    public FirewallFacts? Firewall { get; set; }
    public UpdatesFacts? Updates { get; set; }
    public AntivirusFacts? Antivirus { get; set; }
    public AccountsFacts? Accounts { get; set; }
    public ServicesAndFeaturesFacts? ServicesAndFeatures { get; set; }

    /// <summary>
    /// Safely deserializes raw audit JSON without throwing on empty, malformed, or incompatible payloads.
    /// </summary>
    public static bool TryParse(
        string? json,
        [NotNullWhen(true)] out AuditFacts? facts,
        [NotNullWhen(false)] out string? errorMessage)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            facts = null;
            errorMessage = "Audit JSON payload is empty.";
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip
            });

            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                facts = null;
                errorMessage = "Audit JSON payload must be a JSON object.";
                return false;
            }

            var parsed = doc.RootElement.Deserialize<AuditFacts>(JsonOptions);
            if (parsed is null)
            {
                facts = null;
                errorMessage = "Audit JSON payload could not be deserialized.";
                return false;
            }

            if (parsed.SchemaVersion.HasValue && parsed.SchemaVersion.Value != SupportedSchemaVersion)
            {
                facts = null;
                errorMessage =
                    $"Unsupported audit JSON schema version '{parsed.SchemaVersion.Value}' (expected {SupportedSchemaVersion}).";
                return false;
            }

            // Get-HotFix and Defender timestamps often omit a timezone suffix (DateTimeKind.Unspecified on target PC).
            // When collectedAt includes the target PC's offset, align offset-less timestamps to that same offset.
            if (parsed.CollectedAt.HasValue)
            {
                AlignUnspecifiedTimestampsToTargetOffset(doc.RootElement, parsed, parsed.CollectedAt.Value.Offset);
            }

            facts = parsed;
            errorMessage = null;
            return true;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            facts = null;
            errorMessage = $"Invalid audit JSON payload: {ex.Message}";
            return false;
        }
    }

    private static void AlignUnspecifiedTimestampsToTargetOffset(
        JsonElement root,
        AuditFacts parsed,
        TimeSpan targetOffset)
    {
        if (parsed.Updates?.LastInstalledOn is not null &&
            TryGetRawStringProperty(root, "updates", "lastInstalledOn", out var rawUpdateDate) &&
            !FlexibleNullableDateTimeOffsetConverter.HasExplicitOffset(rawUpdateDate) &&
            DateTime.TryParse(rawUpdateDate, CultureInfo.InvariantCulture, DateTimeStyles.None, out var updateDt))
        {
            parsed.Updates.LastInstalledOn = new DateTimeOffset(DateTime.SpecifyKind(updateDt, DateTimeKind.Unspecified), targetOffset);
        }

        if (parsed.Antivirus?.SignatureLastUpdated is not null &&
            TryGetRawStringProperty(root, "antivirus", "signatureLastUpdated", out var rawSigDate) &&
            !FlexibleNullableDateTimeOffsetConverter.HasExplicitOffset(rawSigDate) &&
            DateTime.TryParse(rawSigDate, CultureInfo.InvariantCulture, DateTimeStyles.None, out var sigDt))
        {
            parsed.Antivirus.SignatureLastUpdated = new DateTimeOffset(DateTime.SpecifyKind(sigDt, DateTimeKind.Unspecified), targetOffset);
        }
    }

    private static bool TryGetRawStringProperty(
        JsonElement root,
        string sectionName,
        string propertyName,
        [NotNullWhen(true)] out string? rawValue)
    {
        rawValue = null;

        foreach (var sectionProp in root.EnumerateObject())
        {
            if (!sectionProp.Name.Equals(sectionName, StringComparison.OrdinalIgnoreCase) ||
                sectionProp.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var innerProp in sectionProp.Value.EnumerateObject())
            {
                if (innerProp.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase) &&
                    innerProp.Value.ValueKind == JsonValueKind.String)
                {
                    rawValue = innerProp.Value.GetString();
                    return !string.IsNullOrWhiteSpace(rawValue);
                }
            }
        }

        return false;
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            AllowTrailingCommas = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            NumberHandling = JsonNumberHandling.AllowReadingFromString
        };
        options.Converters.Add(new FlexibleNullableDateTimeOffsetConverter());
        return options;
    }
}

public sealed class OsFacts
{
    public string? Error { get; set; }
    public string? Caption { get; set; }
    public string? Version { get; set; }
    public string? PsVersion { get; set; }
    public int? PsMajor { get; set; }
}

public sealed class FirewallFacts
{
    public string? Error { get; set; }
    public List<FirewallProfileFacts>? Profiles { get; set; }
}

public sealed class FirewallProfileFacts
{
    public string? Name { get; set; }
    public bool? Enabled { get; set; }
}

public sealed class UpdatesFacts
{
    public string? Error { get; set; }
    public DateTimeOffset? LastInstalledOn { get; set; }
    public string? LatestHotFixId { get; set; }
    public int? HotFixCount { get; set; }
    public string? Source { get; set; }
}

public sealed class AntivirusFacts
{
    public string? Error { get; set; }
    public bool? AntivirusEnabled { get; set; }
    public bool? RealTimeProtectionEnabled { get; set; }
    public int? SignatureAgeDays { get; set; }
    public DateTimeOffset? SignatureLastUpdated { get; set; }
}

public sealed class AccountsFacts
{
    public string? Error { get; set; }
    public GuestAccountFacts? Guest { get; set; }
    public AdministratorsGroupFacts? Administrators { get; set; }
    public PasswordPolicyFacts? PasswordPolicy { get; set; }
}

public sealed class GuestAccountFacts
{
    public string? Error { get; set; }
    public bool? Exists { get; set; }
    public bool? Enabled { get; set; }
}

public sealed class AdministratorsGroupFacts
{
    public string? Error { get; set; }
    public int? Count { get; set; }
    public List<string>? Members { get; set; }
}

public sealed class PasswordPolicyFacts
{
    public string? Error { get; set; }
    public int? MinimumPasswordLength { get; set; }
    public int? PasswordComplexity { get; set; }
    public int? LockoutBadCount { get; set; }
    public string? Source { get; set; }
}

public sealed class ServicesAndFeaturesFacts
{
    public string? Error { get; set; }
    public RemoteRegistryFacts? RemoteRegistry { get; set; }
    public bool? RdpEnabled { get; set; }
    public Smb1Facts? Smb1 { get; set; }
    public TelnetClientFacts? TelnetClient { get; set; }
}

public sealed class RemoteRegistryFacts
{
    public string? Error { get; set; }
    public bool? Exists { get; set; }
    public string? Status { get; set; }
    public string? StartType { get; set; }
}

public sealed class Smb1Facts
{
    public string? Error { get; set; }
    public bool? ServerProtocolEnabled { get; set; }
    public string? FeatureState { get; set; }
}

public sealed class TelnetClientFacts
{
    public string? Error { get; set; }
    public string? FeatureState { get; set; }
}

/// <summary>
/// Parses ISO 8601 date strings with or without timezone offsets into nullable DateTimeOffset.
/// Unparseable or blank date strings deserialize as null so only the affected check becomes Error.
/// </summary>
internal sealed class FlexibleNullableDateTimeOffsetConverter : JsonConverter<DateTimeOffset?>
{
    public override DateTimeOffset? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
            return null;

        if (reader.TokenType != JsonTokenType.String)
            throw new JsonException($"Expected string or null for DateTimeOffset, got {reader.TokenType}.");

        var raw = reader.GetString();
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var trimmed = raw.Trim();
        if (HasExplicitOffset(trimmed))
        {
            return DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dto)
                ? dto
                : null;
        }

        if (DateTime.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
        {
            var unspecified = DateTime.SpecifyKind(dt, DateTimeKind.Unspecified);
            return new DateTimeOffset(unspecified, TimeZoneInfo.Local.GetUtcOffset(unspecified));
        }

        return DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var fallback)
            ? fallback
            : null;
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset? value, JsonSerializerOptions options)
    {
        if (value.HasValue)
        {
            writer.WriteStringValue(value.Value.ToString("o", CultureInfo.InvariantCulture));
        }
        else
        {
            writer.WriteNullValue();
        }
    }

    internal static bool HasExplicitOffset(string value)
    {
        if (value.EndsWith("Z", StringComparison.OrdinalIgnoreCase))
            return true;

        var tIndex = value.IndexOf('T');
        if (tIndex < 0)
            tIndex = value.IndexOf(' ');

        if (tIndex < 0)
            return false;

        var timePart = value[(tIndex + 1)..];
        return timePart.Contains('+') || timePart.Contains('-');
    }
}

