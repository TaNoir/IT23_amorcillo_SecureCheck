using Microsoft.AspNetCore.Http;
using SecureCheck.Web.Services;

namespace SecureCheck.Tests;

public class IdentityPageAccessTests
{
    [Theory]
    [InlineData("/Identity/Account/Login")]
    [InlineData("/Identity/Account/Logout")]
    [InlineData("/Identity/Account/AccessDenied")]
    [InlineData("/Identity/Account/Manage/ChangePassword")]
    [InlineData("/identity/account/login")]   // case-insensitive
    [InlineData("/Identity/Account/Login/")]  // trailing slash
    public void Allowed_identity_pages_are_not_blocked(string path)
    {
        Assert.False(IdentityPageAccess.IsBlocked(new PathString(path)));
    }

    [Theory]
    [InlineData("/Identity/Account/Register")]
    [InlineData("/Identity/Account/RegisterConfirmation")]
    [InlineData("/Identity/Account/ForgotPassword")]
    [InlineData("/Identity/Account/ExternalLogin")]
    [InlineData("/Identity/Account/Manage")]
    [InlineData("/Identity/Account/Manage/PersonalData")]
    [InlineData("/Identity/Account/Manage/DeletePersonalData")]
    [InlineData("/Identity/lib/bootstrap/dist/css/bootstrap.min.css")]
    public void Unused_identity_pages_are_blocked(string path)
    {
        Assert.True(IdentityPageAccess.IsBlocked(new PathString(path)));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/Index")]
    [InlineData("/Admin/Users")]
    [InlineData("/css/site.css")]
    [InlineData("/IdentityStuff")] // not under the /Identity segment
    public void Non_identity_paths_are_not_blocked(string path)
    {
        Assert.False(IdentityPageAccess.IsBlocked(new PathString(path)));
    }
}

