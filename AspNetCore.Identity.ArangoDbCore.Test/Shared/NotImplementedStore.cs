using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
        public class NotImplementedStore :
            IUserPasswordStore<TestUser>,
            IUserClaimStore<TestUser>,
            IUserLoginStore<TestUser>,
            IUserRoleStore<TestUser>,
            IUserEmailStore<TestUser>,
            IUserPhoneNumberStore<TestUser>,
            IUserLockoutStore<TestUser>,
            IUserTwoFactorStore<TestUser>
        {
            public Task<IList<Claim>> GetClaimsAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task AddClaimsAsync(TestUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task ReplaceClaimAsync(TestUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task RemoveClaimsAsync(TestUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetEmailAsync(TestUser user, string email, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<string> GetEmailAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<bool> GetEmailConfirmedAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetEmailConfirmedAsync(TestUser user, bool confirmed, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<TestUser> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<DateTimeOffset?> GetLockoutEndDateAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetLockoutEndDateAsync(TestUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<int> IncrementAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task ResetAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<int> GetAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<bool> GetLockoutEnabledAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetLockoutEnabledAsync(TestUser user, bool enabled, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task AddLoginAsync(TestUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task RemoveLoginAsync(TestUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<IList<UserLoginInfo>> GetLoginsAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<TestUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public void Dispose()
            {
                throw new NotImplementedException();
            }

            public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<string> GetUserNameAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetUserNameAsync(TestUser user, string userName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<TestUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<TestUser> FindByNameAsync(string userName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetPasswordHashAsync(TestUser user, string passwordHash, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<string> GetPasswordHashAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<bool> HasPasswordAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetPhoneNumberAsync(TestUser user, string phoneNumber, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<string> GetPhoneNumberAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<bool> GetPhoneNumberConfirmedAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetPhoneNumberConfirmedAsync(TestUser user, bool confirmed, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetTwoFactorEnabledAsync(TestUser user, bool enabled, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<bool> GetTwoFactorEnabledAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task AddToRoleAsync(TestUser user, string roleName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task RemoveFromRoleAsync(TestUser user, string roleName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<IList<string>> GetRolesAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<bool> IsInRoleAsync(TestUser user, string roleName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<string> GetNormalizedUserNameAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetNormalizedUserNameAsync(TestUser user, string userName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<IList<TestUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<IList<TestUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            Task<IdentityResult> IUserStore<TestUser>.CreateAsync(TestUser user, CancellationToken cancellationToken)
            {
                throw new NotImplementedException();
            }

            Task<IdentityResult> IUserStore<TestUser>.UpdateAsync(TestUser user, CancellationToken cancellationToken)
            {
                throw new NotImplementedException();
            }

            Task<IdentityResult> IUserStore<TestUser>.DeleteAsync(TestUser user, CancellationToken cancellationToken)
            {
                throw new NotImplementedException();
            }

            public Task<string> GetNormalizedEmailAsync(TestUser user, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task SetNormalizedEmailAsync(TestUser user, string normalizedEmail, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }
        }

}
