using System.Security.Claims;
using SecureCheck.Web.Models;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

public class ClaimsPrincipalExtensionsTests
{
    [Fact]
    public void Returns_full_name_claim_when_present()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "admin@securecheck.local"),
            new Claim(AppClaimTypes.FullName, "Evander Amorcillo")
        }, "Test"));

        Assert.Equal("Evander Amorcillo", user.GetFullName());
    }

    [Fact]
    public void Falls_back_to_user_name_when_full_name_missing()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "admin@securecheck.local")
        }, "Test"));

        Assert.Equal("admin@securecheck.local", user.GetFullName());
    }

    [Fact]
    public void Returns_empty_string_for_anonymous_user()
    {
        Assert.Equal(string.Empty, new ClaimsPrincipal(new ClaimsIdentity()).GetFullName());
    }
}

