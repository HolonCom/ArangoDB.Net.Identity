using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using ArangoDBNetStandard;
using ArangoDBNetStandard.DocumentApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace ArangoDb.Net.Identity
{
	/// <summary>
	///     When passing a cancellation token, it will only be used if the operation requires a database interaction.
	/// </summary>
	/// <typeparam name="TUser"></typeparam>
	public class UserStore<TUser> :
			IUserPasswordStore<TUser>,
			IUserRoleStore<TUser>,
			IUserLoginStore<TUser>,
			IUserSecurityStampStore<TUser>,
			IUserEmailStore<TUser>,
			IUserClaimStore<TUser>,
			IUserPhoneNumberStore<TUser>,
			IUserTwoFactorStore<TUser>,
			IUserLockoutStore<TUser>,
			IUserAuthenticationTokenStore<TUser>
		where TUser : IdentityUser
	{
		private readonly ArangoDBClient db;
		private readonly ILogger log;

		public UserStore(ArangoDBClient dbClient, ILogger<UserStore<TUser>> logger)
		{
			log = logger;
			db = dbClient;
		}

		public virtual void Dispose()
		{
			// no need to dispose of anything, mongodb handles connection pooling automatically
		}

		public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken token)
		{
			var ret = await db.Document.PostDocumentAsync(Constants.USER_COLLECTION, user);
			user.Id = ret._id;
			return IdentityResult.Success;
		}

		public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken token)
		{
			if (string.IsNullOrEmpty(user.Id))
			{
				return IdentityResult.Failed(
					new IdentityError{Code = "Id",Description = "User must have an ArangoDB-issued ID for its Id property."});
			}

			await db.Document.PutDocumentAsync($"{Constants.USER_COLLECTION}/{user.Id}", user);
			// todo success based on replace result
			return IdentityResult.Success;
		}

		public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken token)
		{
			if (string.IsNullOrEmpty(user.Id))
			{
				return IdentityResult.Failed(
					new IdentityError{Code = "Id",Description = "User must have an ArangoDB-issued ID for its Id property."});
			}

			await db.Document.DeleteDocumentAsync(Constants.USER_COLLECTION, user.Id);
			// todo success based on delete result
			return IdentityResult.Success;
		}

		public virtual async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
			=> user.Id;

		public virtual async Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
			=> user.UserName;

		public virtual async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
			=> user.UserName = userName;

		// note: again this isn't used by Identity framework so no way to integration test it
		public virtual async Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
			=> user.NormalizedUserName;

		public virtual async Task SetNormalizedUserNameAsync(TUser user, string normalizedUserName, CancellationToken cancellationToken)
			=> user.NormalizedUserName = normalizedUserName;

		public virtual async Task<TUser> FindByIdAsync(string userId, CancellationToken token)
		{
			if (string.IsNullOrEmpty(userId)) return null;
			return await db.Document.GetDocumentAsync<TUser>(Constants.USER_COLLECTION, userId);
		}

		public virtual async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken token)
		{
			// todo low priority exception on duplicates? or better to enforce unique index to ensure this
			var resp = await db.Cursor.PostCursorAsync<TUser>($"for doc in {Constants.USER_COLLECTION} where doc.NormalizedUserName == '{normalizedUserName}' return doc");
			return resp.Result.First();
		}

		public virtual async Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken token)
			=> user.PasswordHash = passwordHash;

		public virtual async Task<string> GetPasswordHashAsync(TUser user, CancellationToken token)
			=> user.PasswordHash;

		public virtual async Task<bool> HasPasswordAsync(TUser user, CancellationToken token)
			=> user.HasPassword();

		public virtual async Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken token)
			=> user.AddRole(normalizedRoleName);

		public virtual async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken token)
			=> user.RemoveRole(normalizedRoleName);

		// todo might have issue, I'm just storing Normalized only now, so I'm returning normalized here instead of not normalized.
		// EF provider returns not normalized here
		// however, the rest of the API uses normalized (add/remove/isinrole) so maybe this approach is better anyways
		// note: could always map normalized to not if people complain
		public virtual async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken token)
		{
			var query = $"for d in UserRoles for r in Roles filter d._from == '{user.Id}' filter d._to == r._id return r.Name";
			var ret = await db.Cursor.PostCursorAsync<string>(query);
			return ret.Result.ToList();
		}

		public virtual async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken token)
		{
			var query = $"for d in UserRoles for r in Roles filter d._from == '{user.Id}' filter r.Name == '{normalizedRoleName}'" +
			            "filter d._to == r._id return r.Name";
			var ret = await db.Cursor.PostCursorAsync<string>(query);
			return ret.Result.First().Equals(normalizedRoleName);
		}

		public virtual async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken token)
		{
			var query = $"for u in Users" +
			            " for d in UserRoles" +
			            "for r in Roles" +
			            $"filter r.Name == '{normalizedRoleName}'" +
			            "filter d._to == r._id" +
			            "filter d._from == u._id" +
			            "return u";
			var ret = await db.Cursor.PostCursorAsync<TUser>(query);
			return ret.Result.ToList();
		}

		public virtual async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken token)
			=> user.AddLogin(login);

		public virtual async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
			=> user.RemoveLogin(loginProvider, providerKey);

		public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken token)
		{
			var query = $"for ul in UserLoginInfo filter ul._from == '{user.Id}' return ul";
			var ret = await db.Cursor.PostCursorAsync<UserLoginInfo>(query);
			return ret.Result.ToList();
		}

		public virtual async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
		{
			var query = $"for ul in UserLoginInfo for u in Users filter ul.loginProvider == '{loginProvider}' filter ul.providerKey == '{providerKey}' filter u._id == ul._from return u";
				var ret = await db.Cursor.PostCursorAsync<TUser>(query);
					return ret.Result.FirstOrDefault();
		}

		public virtual async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken token)
			=> user.SecurityStamp = stamp;

		public virtual async Task<string> GetSecurityStampAsync(TUser user, CancellationToken token)
			=> user.SecurityStamp;

		public virtual async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken token)
			=> user.EmailConfirmed;

		public virtual async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken token)
			=> user.EmailConfirmed = confirmed;

		public virtual async Task SetEmailAsync(TUser user, string email, CancellationToken token)
			=> user.Email = email;

		public virtual async Task<string> GetEmailAsync(TUser user, CancellationToken token)
			=> user.Email;

		// note: no way to integration test as this isn't used by Identity framework
		public virtual async Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
			=> user.NormalizedEmail;

		public virtual async Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
			=> user.NormalizedEmail = normalizedEmail;

		public virtual async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken token)
		{
			var query = $"for u in Users filter u.normalizedEmail == '{normalizedEmail}' return u";
			var ret = await db.Cursor.PostCursorAsync<TUser>(query);
			return ret.Result.First();
		}

		public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken token)
			=> user.Claims.Select(c => c.ToSecurityClaim()).ToList();

		public virtual Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken token)
		{
			foreach (var claim in claims)
			{
				user.AddClaim(claim);
			}
			return Task.FromResult(0);
		}

		public virtual Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken token)
		{
			foreach (var claim in claims)
			{
				user.RemoveClaim(claim);
			}
			return Task.FromResult(0);
		}

		public virtual async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
		{
			user.ReplaceClaim(claim, newClaim);
		}

		public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken token)
		{
			user.PhoneNumber = phoneNumber;
			return Task.FromResult(0);
		}

		public virtual Task<string> GetPhoneNumberAsync(TUser user, CancellationToken token)
		{
			return Task.FromResult(user.PhoneNumber);
		}

		public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken token)
		{
			return Task.FromResult(user.PhoneNumberConfirmed);
		}

		public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken token)
		{
			user.PhoneNumberConfirmed = confirmed;
			return Task.FromResult(0);
		}

		public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken token)
		{
			user.TwoFactorEnabled = enabled;
			return Task.FromResult(0);
		}

		public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken token)
		{
			return Task.FromResult(user.TwoFactorEnabled);
		}

		public virtual async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
		{
			//TODO: serialize & query claims
			return null;
		}

		public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken token)
		{
			DateTimeOffset? dateTimeOffset = user.LockoutEndDateUtc;
			return Task.FromResult(dateTimeOffset);
		}

		public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken token)
		{
			user.LockoutEndDateUtc = lockoutEnd?.UtcDateTime;
			return Task.FromResult(0);
		}

		public virtual Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken token)
		{
			user.AccessFailedCount++;
			return Task.FromResult(user.AccessFailedCount);
		}

		public virtual Task ResetAccessFailedCountAsync(TUser user, CancellationToken token)
		{
			user.AccessFailedCount = 0;
			return Task.FromResult(0);
		}

		public virtual async Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken token)
			=> user.AccessFailedCount;

		public virtual async Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken token)
			=> user.LockoutEnabled;

		public virtual async Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken token)
			=> user.LockoutEnabled = enabled;

		public virtual async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
			=> user.SetToken(loginProvider, name, value);

		public virtual async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
			=> user.RemoveToken(loginProvider, name);

		public virtual async Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
			=> user.GetTokenValue(loginProvider, name);
	}
}
