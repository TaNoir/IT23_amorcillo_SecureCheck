using System.Text.RegularExpressions;

namespace SecureCheck.Tests;

/// <summary>
/// Razor HTML-encodes values, but the browser decodes attributes before running inline JS,
/// so @Model values inside onclick="..." can break the script or inject code.
/// Use data-confirm="..." (handled in site.js) instead.
/// </summary>
public class RazorViewSafetyTests
{
    private static readonly Regex InlineHandlerWithRazor =
        new(@"\son[a-z]+\s*=\s*""[^""]*@", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    [Fact]
    public void Inline_event_handlers_never_contain_razor_expressions()
    {
        var webRoot = Path.Combine(FindRepoRoot(), "src", "SecureCheck.Web");

        var offenders = Directory
            .EnumerateFiles(webRoot, "*.cshtml", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") &&
                        !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .SelectMany(f => File.ReadLines(f)
                .Select((line, i) => (File: f, Line: i + 1, Text: line)))
            .Where(x => InlineHandlerWithRazor.IsMatch(x.Text))
            .Select(x => $"{Path.GetRelativePath(webRoot, x.File)}:{x.Line}")
            .ToList();

        Assert.True(offenders.Count == 0, "Inline JS handlers with Razor values: " + string.Join(", ", offenders));
    }

    [Fact]
    public void Site_js_handles_data_confirm()
    {
        var siteJs = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "SecureCheck.Web", "wwwroot", "js", "site.js"));

        Assert.Contains("data-confirm", siteJs);
        Assert.Contains("preventDefault", siteJs);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SecureCheck.sln")))
            dir = dir.Parent;

        return dir?.FullName ?? throw new InvalidOperationException("Could not find SecureCheck.sln above the test output folder.");
    }
}

