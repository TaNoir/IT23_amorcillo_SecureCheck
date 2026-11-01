using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;

namespace SecureCheck.Web.Services;

/// <summary>
/// Safely converts remediation guidance containing backticked commands (e.g. `Update-MpSignature`)
/// into HTML where backticked segments are wrapped in &lt;code&gt; tags and all text—both inside and
/// outside backticks—is HTML-encoded so XSS is impossible and placeholders like &lt;name&gt; remain visible.
/// </summary>
public static class RemediationFormatter
{
    public static string FormatToHtml(string? remediation)
    {
        if (string.IsNullOrEmpty(remediation))
            return string.Empty;

        var encoder = HtmlEncoder.Default;
        var sb = new StringBuilder(remediation.Length + 32);
        var pos = 0;

        while (pos < remediation.Length)
        {
            var openTick = remediation.IndexOf('`', pos);
            if (openTick < 0)
            {
                sb.Append(encoder.Encode(remediation[pos..]));
                break;
            }

            if (openTick > pos)
            {
                sb.Append(encoder.Encode(remediation[pos..openTick]));
            }

            var closeTick = remediation.IndexOf('`', openTick + 1);
            if (closeTick < 0)
            {
                // Unmatched trailing backtick: render remaining text literally.
                sb.Append(encoder.Encode(remediation[openTick..]));
                break;
            }

            if (closeTick == openTick + 1)
            {
                // Empty `` pair: render literally and continue scanning.
                sb.Append(encoder.Encode("``"));
                pos = closeTick + 1;
                continue;
            }

            var command = remediation[(openTick + 1)..closeTick];
            sb.Append("<code class=\"sc-fix-cmd\">");
            sb.Append(encoder.Encode(command));
            sb.Append("</code>");

            pos = closeTick + 1;
        }

        return sb.ToString();
    }

    public static HtmlString ToHtmlString(string? remediation) =>
        new(FormatToHtml(remediation));
}

