using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    public class NoopUserStore: IUserStore<TestUser>
    {
        public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(user.UserName);
        }

        public Task SetUserNameAsync(TestUser user, string userName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<TestUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<TestUser>(null);
        }

        public Task<TestUser> FindByNameAsync(string userName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<TestUser>(null);
        }

        public void Dispose()
        {
        }

        public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<string> GetNormalizedUserNameAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<string>(null);
        }

        public Task SetNormalizedUserNameAsync(TestUser user, string userName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

    }
}
