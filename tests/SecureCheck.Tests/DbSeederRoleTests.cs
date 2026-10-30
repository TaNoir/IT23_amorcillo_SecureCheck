using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using SecureCheck.Web.Data;
using SecureCheck.Web.Models;

namespace SecureCheck.Tests;

public class DbSeederRoleTests
{
    private static RoleManager<IdentityRole> CreateRoleManager(InMemoryRoleStore store) =>
        new(store,
            new[] { new RoleValidator<IdentityRole>() },
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            NullLogger<RoleManager<IdentityRole>>.Instance);

    [Fact]
    public async Task Creates_the_three_roles()
    {
        var store = new InMemoryRoleStore();
        var roleManager = CreateRoleManager(store);

        await DbSeeder.EnsureRolesAsync(roleManager, NullLogger.Instance);

        Assert.Equal(
            AppRoles.All.OrderBy(r => r),
            store.Roles.Select(r => r.Name!).OrderBy(r => r));
    }

    [Fact]
    public async Task Running_twice_does_not_duplicate_roles()
    {
        var store = new InMemoryRoleStore();
        var roleManager = CreateRoleManager(store);

        await DbSeeder.EnsureRolesAsync(roleManager, NullLogger.Instance);
        await DbSeeder.EnsureRolesAsync(roleManager, NullLogger.Instance);

        Assert.Equal(3, store.Roles.Count);
    }

    /// <summary>Minimal role store so RoleManager can run without a database.</summary>
    private sealed class InMemoryRoleStore : IRoleStore<IdentityRole>
    {
        public List<IdentityRole> Roles { get; } = new();

        public Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken ct)
        {
            Roles.Add(role);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken ct) => Task.FromResult(IdentityResult.Success);

        public Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken ct)
        {
            Roles.Remove(role);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken ct) => Task.FromResult(role.Id);
        public Task<string?> GetRoleNameAsync(IdentityRole role, CancellationToken ct) => Task.FromResult(role.Name);

        public Task SetRoleNameAsync(IdentityRole role, string? roleName, CancellationToken ct)
        {
            role.Name = roleName;
            return Task.CompletedTask;
        }

        public Task<string?> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken ct) => Task.FromResult(role.NormalizedName);

        public Task SetNormalizedRoleNameAsync(IdentityRole role, string? normalizedName, CancellationToken ct)
        {
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        public Task<IdentityRole?> FindByIdAsync(string roleId, CancellationToken ct) =>
            Task.FromResult(Roles.FirstOrDefault(r => r.Id == roleId));

        public Task<IdentityRole?> FindByNameAsync(string normalizedRoleName, CancellationToken ct) =>
            Task.FromResult(Roles.FirstOrDefault(r => r.NormalizedName == normalizedRoleName));

        public void Dispose() { }
    }
}

