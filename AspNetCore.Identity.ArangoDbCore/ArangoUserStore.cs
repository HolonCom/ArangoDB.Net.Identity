using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Extensions;
using ArangoDBNetStandard;
using AspNetCore.Identity.ArangoDbCore.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using AspNetCore.Identity.ArangoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Internal;
using Microsoft.Extensions.Logging;

namespace AspNetCore.Identity.ArangoDbCore
{
    /// <summary>
    /// Represents a new instance of a persistence store for users, using the default implementation
    /// of <see cref="IdentityUser{TKey}"/> with a string as a primary key.
    /// </summary>
    public class ArangoUserStore : ArangoUserStore<ArangoIdentityUser<string>>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="MongoUserStore"/>.
        /// </summary>
        /// <param name="context">The <see cref="MongoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoUserStore(IArangoDbContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <summary>
    /// Creates a new instance of a persistence store for the specified user type.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    public class ArangoUserStore<TUser> : ArangoUserStore<TUser, ArangoIdentityRole<string>, IArangoDbContext, string>
        where TUser : ArangoIdentityUser<string>, new()
    {
        /// <summary>
        /// Constructs a new instance of <see cref="MongoUserStore{TUser}"/>.
        /// </summary>
        /// <param name="context">The <see cref="MongoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoUserStore(IArangoDbContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    public class ArangoUserStore<TUser, TRole, TContext> : ArangoUserStore<TUser, TRole, TContext, string>
        where TUser : ArangoIdentityUser<string>, new()
        where TRole : ArangoIdentityRole<string>, new()
        where TContext : IArangoDbContext
    {
        /// <summary>
        /// Constructs a new instance of <see cref="MongoUserStore{TUser, TRole, TContext}"/>.
        /// </summary>
        /// <param name="context">The <see cref="MongoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoUserStore(TContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    public class ArangoUserStore<TUser, TRole, TContext, TKey> :
        ArangoUserStore<TUser, TRole, TContext, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>,
            IdentityUserLogin<TKey>, IdentityUserToken<TKey>, IdentityRoleClaim<TKey>>
        where TUser : ArangoIdentityUser<TKey>, new()
        where TRole : ArangoIdentityRole<TKey>, new()
        where TContext : IArangoDbContext
        where TKey : class, IEquatable<TKey>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="ArangoUserStore{TUser, TRole, TContext, TKey}"/>.
        /// </summary>
        /// <param name="context">The <see cref="ArangoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoUserStore(TContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }


    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    /// <typeparam name="TUserClaim">The type representing a claim.</typeparam>
    /// <typeparam name="TUserRole">The type representing a user role.</typeparam>
    /// <typeparam name="TUserLogin">The type representing a user external login.</typeparam>
    /// <typeparam name="TUserToken">The type representing a user token.</typeparam>
    /// <typeparam name="TRoleClaim">The type representing a role claim.</typeparam>
    public class ArangoUserStore<TUser, TRole, TContext, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim> :
        UserStoreBase<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>,
        IUserAuthenticationTokenStore<TUser>
        where TUser : ArangoIdentityUser<TKey>, new()
        where TRole : ArangoIdentityRole<TKey>, new()
        where TContext : IArangoDbContext
        where TKey : class, IEquatable<TKey>
        where TUserClaim : IdentityUserClaim<TKey>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserToken : IdentityUserToken<TKey>, new()
        where TRoleClaim : IdentityRoleClaim<TKey>, new()
    {

        private readonly ArangoDBClient db;
        private readonly ILogger log;

        /// <summary>
        /// Creates a new instance of the store.
        /// </summary>
        /// <param name="context">The context used to access the store.</param>
        /// <param name="dbClient">The Arango database client for the application.</param>
        /// <param name="logger">The logger.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
        public ArangoUserStore(TContext context,
            ILogger<ArangoUserStore<TUser, TRole, TContext, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>> logger,
            IdentityErrorDescriber describer = null)
            : base(describer ?? new IdentityErrorDescriber())
        {
            log = logger;
            db = context.Client;

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            Context = context;
        }

        public ArangoUserStore(TContext context, IdentityErrorDescriber describer = null) : base(describer ?? new IdentityErrorDescriber())
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            Context = context;
        }

        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        private static TContext Context { get; set; }

        /// <summary>Saves the current store.</summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected Task SaveChanges(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
        /// <summary>
        /// Creates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the creation operation.</returns>
        public override async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            //TODO: Figure out how to get the ID back to the user
            cancellationToken.ThrowIfCancellationRequested();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var u = user as ArangoIdentityUser;
            var ret = await db.Document.PostDocumentAsync(Constants.USER_COLLECTION, u);
            //user.Id = ret._id;
            return IdentityResult.Success;
        }

        /// <summary>
        /// Updates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var oldStamp = user.ConcurrencyStamp;
            user.ConcurrencyStamp = user._rev;
            var ret = await db.Document.PutDocumentAsync(user._id, user);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.Claims.Clear();
            user.Roles.Clear();
            user.Logins.Clear();
            user.Tokens.Clear();

            await db.Document.DeleteDocumentAsync(Constants.USER_COLLECTION, user._id);
            // todo success based on delete result
            return IdentityResult.Success;
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public override async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var user = await db.Document.GetDocumentAsync<ArangoIdentityUser>(Constants.USER_COLLECTION, userId);
            return user as TUser;
        }

        // /// <summary>
        // /// Converts the provided <paramref name="id"/> to a strongly typed key object.
        // /// </summary>
        // /// <param name="id">The id to convert.</param>
        // /// <returns>An instance of <typeparamref name="TKey"/> representing the provided <paramref name="id"/>.</returns>
        // public override TKey ConvertIdFromString(string id)
        // {
        //     return id.ToTKey<TKey>();
        // }


        /// <summary>
        /// Finds and returns a user, if any, who has the specified normalized user name.
        /// </summary>
        /// <param name="normalizedUserName">The normalized user name to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
        /// </returns>
        public override async Task<TUser> FindByNameAsync(string normalizedUserName,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var resp = await db.Cursor.PostCursorAsync<ArangoIdentityUser>($"for doc in {Constants.USER_COLLECTION} where doc.NormalizedUserName == '{normalizedUserName}' return doc");
            var user = resp.Result.First();
            //user.Id = user._id;
            return user as TUser;
        }

        /// <summary>
        /// Return a role with the normalized name if it exists.
        /// </summary>
        /// <param name="normalizedRoleName">The normalized role name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The role if it exists.</returns>
        protected override async Task<TRole> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            var ret = await db.Cursor.PostCursorAsync<ArangoIdentityRole>(
                $"for r in {Constants.ROLE_COLLECTION} filter r.Name == '{normalizedRoleName}' return r");
            var role = ret.Result.First();
            role.Id = role._id;
            return role as TRole;
        }

        /// <summary>
        /// Return a user role for the userId and roleId if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="roleId">The role's id.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user role if it exists.</returns>
        protected override async Task<TUserRole> FindUserRoleAsync(TKey userId, TKey roleId, CancellationToken cancellationToken)
        {

            var ret = await db.Cursor.PostCursorAsync<ArangoIdentityUserRole<TKey>>(
                $"for r in UserRoles filter r._from == '{userId}' filter r._to == '{roleId}' return r");

            var ura = ret.Result.First();

            ura.RoleId = ura._to as TKey;
            ura.UserId = ura._from as TKey;

            return ura as TUserRole;
        }

        /// <summary>
        /// Return a user with the matching userId if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user if it exists.</returns>
        protected override async Task<TUser> FindUserAsync(TKey userId, CancellationToken cancellationToken)
        {
            var ret = await db.Document.GetDocumentAsync<ArangoIdentityUser>(userId.ToString());
            //ret.Id = ret._id;

            return ret as TUser;
        }

        /// <summary>
        /// Return a user login with the matching userId, provider, providerKey if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        protected override async Task<TUserLogin> FindUserLoginAsync(TKey userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            //for u in Users filter u.userId == 'lucas' return u

            var ret = await db.Cursor.PostCursorAsync<ArangoIdentityUserLogin<TKey>>(
                $"for r in {Constants.USER_LOGIN_INFO_EDGE} filter r.userId == '{userId}' filter r.loginProvider == '{loginProvider}' filter r.providerKey == '{providerKey}' return r");
            var ul = ret.Result.First();
            return ul as TUserLogin;
        }

        /// <summary>
        /// Return a user login with  provider, providerKey if it exists.
        /// </summary>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        protected override async Task<TUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var ret = await db.Cursor.PostCursorAsync<ArangoIdentityUserLogin<TKey>>(
                $"for u in {Constants.USER_LOGIN_INFO_EDGE} filter user.loginProvider == '{loginProvider}' filter user.providerKey == '{providerKey}' return u;");
            var ul = ret.Result.First();
            return ul as TUserLogin;
        }

        /// <summary>
        /// Adds the given <paramref name="normalizedRoleName"/> to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the role to.</param>
        /// <param name="normalizedRoleName">The role to add.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        /// <remarks>This query assumes that the role exists in the Role collection.</remarks>
        public override async Task AddToRoleAsync(TUser user, string normalizedRoleName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentException("Value", nameof(normalizedRoleName));
            }

            var query = $"for u in Users filter u._id == '{user._id}'" +
                        $"for r in Roles filter r.Name == '{normalizedRoleName}'" +
                        "insert {_from: u._id,_to: r._id} in UserRoles";
            await db.Cursor.PostCursorAsync<string>(query);
        }

        /// <summary>
        /// Removes the given <paramref name="normalizedRoleName"/> from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the role from.</param>
        /// <param name="normalizedRoleName">The role to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(normalizedRoleName));
            }

            var query = "for u in Users for r in Roles for ur in UserRoles " +
                $"filter r.Name == '{normalizedRoleName}' filter u.userId == '{user._id}'" +
            "filter ur._from == u._id filter ur._to == r._id remove ur in UserRoles";

            await db.Cursor.PostCursorAsync<string>(query);
        }

        /// <summary>
        /// Retrieves the roles the specified <paramref name="user"/> is a member of.
        /// </summary>
        /// <param name="user">The user whose roles should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the roles the user is a member of.</returns>
        public override async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var query =
                $"for r in Roles for ur in UserRoles filter ur._from == '{user._id}' filter ur._to == r._id return r.Name";
            var ret = await db.Cursor.PostCursorAsync < List<string>>(query);
            return ret.Result.First();
        }

        /// <summary>
        /// Returns a flag indicating if the specified user is a member of the give <paramref name="normalizedRoleName"/>.
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param>
        /// <param name="normalizedRoleName">The role to check membership of</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> containing a flag indicating if the specified user is a member of the given group. If the
        /// user is a member of the group the returned value with be true, otherwise it will be false.</returns>
        public override async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(normalizedRoleName));
            }

            var query = $"for r in Roles for ur in UserRoles filter r.Name == '{normalizedRoleName}'" +
                        $" filter ur._from == '{user._id}' filter ur._to == r._id return r.Name";

            var ret = await db.Cursor.PostCursorAsync<List<string>>(query);

            return ret.Count != 0;
        }

        /// <summary>
        /// Get the claims associated with the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose claims should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a user.</returns>
#pragma warning disable 1998
        public override async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
#pragma warning restore 1998
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return user.Claims.Select(e => e.ToClaim()).ToList();
        }

        /// <summary>
        /// Adds the <paramref name="claims"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claim to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }
            var addedSome = false;
            foreach (var claim in claims)
            {
                if (user.AddClaim(claim))
                {
                    addedSome = true;
                }
            }

            if (addedSome) await db.Document.PutDocumentAsync($"Users/{user._id}", user);

        }

        /// <summary>
        /// Replaces the <paramref name="claim"/> on the specified <paramref name="user"/>, with the <paramref name="newClaim"/>.
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim replace.</param>
        /// <param name="newClaim">The new claim replacing the <paramref name="claim"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            if (user.ReplaceClaim(claim, newClaim))
            {
                await db.Document.PutDocumentAsync($"Users/{user._id}", user);
            }
        }

        /// <summary>
        /// Removes the <paramref name="claims"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the claims from.</param>
        /// <param name="claims">The claim to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }
            if (user.RemoveClaims(claims))
            {
                await db.Document.PutDocumentAsync($"Users/{user._id}", user);
            }
        }

        /// <summary>
        /// Adds the <paramref name="login"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the login to.</param>
        /// <param name="login">The login to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate
        /// notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task AddLoginAsync(TUser user, UserLoginInfo login,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            if (user.AddLogin(login))
            {
                var u = login as ArangoUserLoginInfo;
                u._from = user._id;
                u._to = user._id;
                var ret = await db.Document.PutDocumentAsync($"UserLoginInfo", u);
            }

        }

        /// <summary>
        /// Removes the <paramref name="loginProvider"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the login from.</param>
        /// <param name="loginProvider">The login to remove from the user.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var entry = user.Logins.FirstOrDefault(e => e.LoginProvider == loginProvider && e.ProviderKey == providerKey);
            if (entry != null)
            {
                user.RemoveLogin(entry);

                var query = "for ul in UserLoginInfo " +
                            $"filter ul._from == '{user._id}' " +
                            $"filter ul.loginProvider == '{loginProvider}' " +
                            "Remove ul in UserLoginInfo";
                var ret = await db.Cursor.PostCursorAsync<string>(query);
                if (ret.Error) log.LogError(ret.Result.First());
            }
        }

        /// <summary>
        /// Retrieves the associated logins for the specified <param ref="user"/>.
        /// </summary>
        /// <param name="user">The user whose associated logins to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
        /// </returns>
        public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return user.Logins.ToList();
        }

        /// <summary>
        /// Retrieves the user associated with the specified login provider and login provider key.
        /// </summary>
        /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
        /// </returns>
        public override async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var userLogin = await FindUserLoginAsync(loginProvider, providerKey, cancellationToken);
            if (userLogin != null)
            {
                return await FindUserAsync(userLogin.UserId, cancellationToken);
            }
            return null;
        }

        /// <summary>
        /// Gets the user, if any, associated with the specified, normalized email address.
        /// </summary>
        /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
        /// </returns>
        public override async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var query = $"for u in Users filter u.NormalizedEmail == '{normalizedEmail}' return u";
            var ret = await db.Cursor.PostCursorAsync<ArangoIdentityUser>(query);
            return ret.Result.FirstOrDefault() as TUser;
        }

        /// <summary>
        /// Retrieves all users with the specified claim.
        /// </summary>
        /// <param name="claim">The claim whose users should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> contains a list of users, if any, that contain the specified claim.
        /// </returns>
        public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            //TODO: verify/fix query
            var query = $"for u in Users filter u.Claims.Type == '{claim.Type}' filter u.Claims.Value == '{claim.Value}' return u";
            var ret = await db.Cursor.PutCursorAsync<ArangoIdentityUser>(query);
            return ret.Result.ToList() as IList<TUser>;
        }

        /// <summary>
        /// Retrieves all users in the specified role.
        /// </summary>
        /// <param name="normalizedRoleName">The role whose users should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> contains a list of users, if any, that are in the specified role.
        /// </returns>
        public override async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            var query = $"for u in Users" +
                        " for d in UserRoles" +
                        "for r in Roles" +
                        $"filter r.Name == '{normalizedRoleName}'" +
                        "filter d._to == r._id" +
                        "filter d._from == u._id" +
                        "return u";
            var ret = await db.Cursor.PostCursorAsync<ArangoIdentityUser>(query);
            return ret.Result.ToList() as IList<TUser>;
        }

        /// <summary>
        /// Get the user from the Users collection.
        /// </summary>
        /// <param name="userId">The user to fetch.</param>
        /// <returns>The user as a <see cref="TUser"/></returns>
        public async Task<TUser> GetUserByIdAsync(string userId)
        {
            var query = $"for u in users filter u._id == '{userId}' return u";
            var ret = await db.Cursor.PostCursorAsync<ArangoIdentityUser>(query);
            return ret.Result.FirstOrDefault() as TUser;
        }

        public async Task UpdateUser(TUser user)
        {
            await db.Document.PostDocumentAsync("Users", user as ArangoIdentityUser);
        }

        #region Token Management
        /// <summary>
        /// Find a user token if it exists.
        /// </summary>
        /// <param name="user">The token owner.</param>
        /// <param name="loginProvider">The login provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user token if it exists.</returns>
        protected override Task<TUserToken> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            return Task.FromResult((TUserToken)user.GetToken(loginProvider, name));
        }

        /// <summary>
        /// Add a new user token.
        /// </summary>
        /// <param name="token">The token to be added.</param>
        /// <returns></returns>
        protected override async Task AddUserTokenAsync(TUserToken token)
        {

            var user = await GetUserByIdAsync(token.UserId as string);
            if (user != null)
            {
                if (user.AddUserToken(token))
                {
                    await UpdateUser(user);
                }
            }
        }

        /// <summary>
        /// Remove a new user token.
        /// </summary>
        /// <param name="token">The token to be removed.</param>
        /// <returns></returns>
        protected override async Task RemoveUserTokenAsync(TUserToken token)
        {
            var user = await GetUserByIdAsync(token.UserId as string);
            if (user != null)
            {
                if (user.RemoveUserToken(token))
                {
                    await UpdateUser(user);
                }
            }
        }

        #endregion

        #region UserStoreBase overrides
        /// <summary>
        /// Sets the given <paramref name="userName" /> for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="userName">The user name to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.UserName != userName)
            {
                user.UserName = userName;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the given normalized name for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="normalizedName">The normalized name to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.NormalizedUserName != normalizedName)
            {
                user.NormalizedUserName = normalizedName;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the password hash for a user.
        /// </summary>
        /// <param name="user">The user to set the password hash for.</param>
        /// <param name="passwordHash">The password hash to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.PasswordHash != passwordHash)
            {
                user.PasswordHash = passwordHash;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the flag indicating whether the specified <paramref name="user"/>'s email address has been confirmed or not.
        /// </summary>
        /// <param name="user">The user whose email confirmation status should be set.</param>
        /// <param name="confirmed">A flag indicating if the email address has been confirmed, true if the address is confirmed otherwise false.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public override async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (user.EmailConfirmed != confirmed)
            {
                user.EmailConfirmed = confirmed;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the <paramref name="email"/> address for a <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email should be set.</param>
        /// <param name="email">The email to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public override async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.Email != email)
            {
                user.Email = email;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the normalized email for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email address to set.</param>
        /// <param name="normalizedEmail">The normalized email to set for the specified <paramref name="user"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public override async Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.NormalizedEmail != normalizedEmail)
            {
                user.NormalizedEmail = normalizedEmail;
                await UpdateUser(user);

            }
            user.NormalizedEmail = normalizedEmail;
        }

        /// <summary>
        /// Locks out a user until the specified end date has passed. Setting a end date in the past immediately unlocks a user.
        /// </summary>
        /// <param name="user">The user whose lockout date should be set.</param>
        /// <param name="lockoutEnd">The <see cref="DateTimeOffset"/> after which the <paramref name="user"/>'s lockout should end.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.LockoutEnd != lockoutEnd)
            {
                user.LockoutEnd = lockoutEnd;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Records that a failed access has occurred, incrementing the failed access count.
        /// </summary>
        /// <param name="user">The user whose cancellation count should be incremented.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the incremented failed access count.</returns>
        public override async Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.AccessFailedCount++;
            await UpdateUser(user);
            return user.AccessFailedCount;
        }

        /// <summary>
        /// Resets a user's failed access count.
        /// </summary>
        /// <param name="user">The user whose failed access count should be reset.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        /// <remarks>This is typically called after the account is successfully accessed.</remarks>
        public override async Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.AccessFailedCount != 0)
            {
                user.AccessFailedCount = 0;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Set the flag indicating if the specified <paramref name="user"/> can be locked out..
        /// </summary>
        /// <param name="user">The user whose ability to be locked out should be set.</param>
        /// <param name="enabled">A flag indicating if lock out can be enabled for the specified <paramref name="user"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.LockoutEnabled != enabled)
            {
                user.LockoutEnabled = enabled;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the telephone number for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose telephone number should be set.</param>
        /// <param name="phoneNumber">The telephone number to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (user.PhoneNumber != phoneNumber)
            {
                user.PhoneNumber = phoneNumber;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets a flag indicating if the specified <paramref name="user"/>'s phone number has been confirmed..
        /// </summary>
        /// <param name="user">The user whose telephone number confirmation status should be set.</param>
        /// <param name="confirmed">A flag indicating whether the user's telephone number has been confirmed.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.PhoneNumberConfirmed != confirmed)
            {
                user.PhoneNumberConfirmed = confirmed;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the provided security <paramref name="stamp"/> for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param>
        /// <param name="stamp">The security stamp to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (stamp == null)
            {
                throw new ArgumentNullException(nameof(stamp));
            }

            if (user.SecurityStamp != stamp)
            {
                user.SecurityStamp = stamp;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
        /// <param name="enabled">A flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (user.TwoFactorEnabled != enabled)
            {
                user.TwoFactorEnabled = enabled;
                await UpdateUser(user);
            }
        }

        /// <summary>
        /// Sets the token value for a particular user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="value">The value of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var token = await FindTokenAsync(user, loginProvider, name, cancellationToken);
            if (token == null)
            {
                if (user.AddUserToken(CreateUserToken(user, loginProvider, name, value)))
                {
                    await UpdateUser(user);
                }
                //await AddUserTokenAsync(CreateUserToken(user, loginProvider, name, value));
            }
            else
            {
                if (user.SetToken(token, value))
                {
                    await UpdateUser(user);
                }
            }
        }

        /// <summary>
        /// Deletes a token for a user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var entry = await FindTokenAsync(user, loginProvider, name, cancellationToken);
            if (entry != null)
            {
                if (user.RemoveUserToken(entry))
                {
                    await UpdateUser(user);
                }
            }
        }

        /// <summary>
        /// Returns the token value.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var entry = await FindTokenAsync(user, loginProvider, name, cancellationToken);
            return entry?.Value;
        }

        private const string InternalLoginProvider = "[AspNetUserStore]";
        private const string AuthenticatorKeyTokenName = "AuthenticatorKey";
        private const string RecoveryCodeTokenName = "RecoveryCodes";

        /// <summary>
        /// Sets the authenticator key for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose authenticator key should be set.</param>
        /// <param name="key">The authenticator key to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
            => SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);

        /// <summary>
        /// Get the authenticator key for the specified <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the security stamp for the specified <paramref name="user"/>.</returns>
        public override Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
            => GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken);

        /// <summary>
        /// Returns how many recovery code are still valid for a user.
        /// </summary>
        /// <param name="user">The user who owns the recovery code.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The number of valid recovery codes for the user..</returns>
        public override async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var mergedCodes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken) ?? "";
            if (mergedCodes.Length > 0)
            {
                return mergedCodes.Split(';').Length;
            }
            return 0;
        }

        /// <summary>
        /// Updates the recovery codes for the user while invalidating any previous recovery codes.
        /// </summary>
        /// <param name="user">The user to store new recovery codes for.</param>
        /// <param name="recoveryCodes">The new recovery codes for the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The new recovery codes for the user.</returns>
        public override Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
        {
            var mergedCodes = string.Join(";", recoveryCodes);
            return SetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, mergedCodes, cancellationToken);
        }

        /// <summary>
        /// Returns whether a recovery code is valid for a user. Note: recovery codes are only valid
        /// once, and will be invalid after use.
        /// </summary>
        /// <param name="user">The user who owns the recovery code.</param>
        /// <param name="code">The recovery code to use.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>True if the recovery code was found for the user.</returns>
        public override async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (code == null)
            {
                throw new ArgumentNullException(nameof(code));
            }

            var mergedCodes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken) ?? "";
            var splitCodes = mergedCodes.Split(';');
            if (!splitCodes.Contains(code)) return false;
            var updatedCodes = new List<string>(splitCodes.Where(s => s != code));
            await ReplaceCodesAsync(user, updatedCodes, cancellationToken);
            return true;
        }

        public override IQueryable<TUser> Users { get; }

        #endregion


    }
}
