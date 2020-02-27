using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    public class EmptyStore :
        IUserPasswordStore<TestUser>,
        IUserClaimStore<TestUser>,
        IUserLoginStore<TestUser>,
        IUserEmailStore<TestUser>,
        IUserPhoneNumberStore<TestUser>,
        IUserLockoutStore<TestUser>,
        IUserTwoFactorStore<TestUser>,
        IUserRoleStore<TestUser>,
        IUserSecurityStampStore<TestUser>
    {
        public Task<IList<Claim>> GetClaimsAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IList<Claim>>(new List<Claim>());
        }

        public Task AddClaimsAsync(TestUser user, IEnumerable<Claim> claim,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task ReplaceClaimAsync(TestUser user, Claim claim, Claim newClaim,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task RemoveClaimsAsync(TestUser user, IEnumerable<Claim> claim,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task SetEmailAsync(TestUser user, string email, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult("");
        }

        public Task<bool> GetEmailConfirmedAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task SetEmailConfirmedAsync(TestUser user, bool confirmed, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<TestUser> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<TestUser>(null);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TestUser user,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<DateTimeOffset?>(DateTimeOffset.MinValue);
        }

        public Task SetLockoutEndDateAsync(TestUser user, DateTimeOffset? lockoutEnd,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task ResetAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<bool> GetLockoutEnabledAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task SetLockoutEnabledAsync(TestUser user, bool enabled, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task AddLoginAsync(TestUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task RemoveLoginAsync(TestUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IList<UserLoginInfo>>(new List<UserLoginInfo>());
        }

        public Task<TestUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<TestUser>(null);
        }

        public void Dispose()
        {
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

        public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken cancellationToken = default)
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

        public Task SetPasswordHashAsync(TestUser user, string passwordHash,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<string>(null);
        }

        public Task<bool> HasPasswordAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task SetPhoneNumberAsync(TestUser user, string phoneNumber,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult("");
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task SetPhoneNumberConfirmedAsync(TestUser user, bool confirmed,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task AddToRoleAsync(TestUser user, string roleName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task RemoveFromRoleAsync(TestUser user, string roleName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<IList<string>> GetRolesAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IList<string>>(new List<string>());
        }

        public Task<bool> IsInRoleAsync(TestUser user, string roleName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task SetSecurityStampAsync(TestUser user, string stamp, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult("");
        }

        public Task SetTwoFactorEnabledAsync(TestUser user, bool enabled, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
        }

        public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<string>(null);
        }

        public Task<string> GetUserNameAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<string>(null);
        }

        public Task<string> GetNormalizedUserNameAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<string>(null);
        }

        public Task SetNormalizedUserNameAsync(TestUser user, string userName,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }

        public Task<IList<TestUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IList<TestUser>>(new List<TestUser>());
        }

        public Task<IList<TestUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IList<TestUser>>(new List<TestUser>());
        }

        public Task<string> GetNormalizedEmailAsync(TestUser user, CancellationToken cancellationToken = default)
        {
            return Task.FromResult("");
        }

        public Task SetNormalizedEmailAsync(TestUser user, string normalizedEmail,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }
    }
}
