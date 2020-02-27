using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Extensions;
using AspNetCore.Identity.ArangoDbCore.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using AspNetCore.Identity.ArangoDbCore.Models;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore
{
    /// <summary>
    /// Creates a new instance of a persistence store for roles.
    /// </summary>
    /// <typeparam name="TRole">The type of the class representing a role</typeparam>
    public class ArangoRoleStore<TRole> : ArangoRoleStore<TRole, ArangoDbContext, string>
        where TRole : ArangoIdentityRole
    {
        /// <summary>
        /// Constructs a new instance of <see cref="ArangoRoleStore{TRole}"/>.
        /// </summary>
        /// <param name="context">The <see cref="IArangoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoRoleStore(IArangoDbContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <summary>
    /// Creates a new instance of a persistence store for roles.
    /// </summary>
    /// <typeparam name="TRole">The type of the class representing a role.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    public class ArangoRoleStore<TRole, TContext> : ArangoRoleStore<TRole, TContext, string>
        where TRole : ArangoIdentityRole
        where TContext : IArangoDbContext
    {
        /// <summary>
        /// Constructs a new instance of <see cref="ArangoRoleStore{TRole, TContext}"/>.
        /// </summary>
        /// <param name="context">The <see cref="IArangoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoRoleStore(IArangoDbContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <summary>
    /// Creates a new instance of a persistence store for roles.
    /// </summary>
    /// <typeparam name="TRole">The type of the class representing a role.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    public class ArangoRoleStore<TRole, TContext, TKey> : ArangoRoleStore<TRole, TContext, TKey, ArangoIdentityUserRole<TKey>,
            ArangoIdentityRoleClaim<TKey>>,
        IQueryableRoleStore<TRole>,
        IRoleClaimStore<TRole>
        where TRole : ArangoIdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TContext : IArangoDbContext
    {
        /// <summary>
        /// Constructs a new instance of <see cref="ArangoRoleStore{TRole, TContext, TKey}"/>.
        /// </summary>
        /// <param name="context">The <see cref="IArangoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoRoleStore(IArangoDbContext context, IdentityErrorDescriber describer = null) : base(context, describer) { }
    }

    /// <summary>
    /// Creates a new instance of a persistence store for roles.
    /// </summary>
    /// <typeparam name="TRole">The type of the class representing a role.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    /// <typeparam name="TUserRole">The type of the class representing a user role.</typeparam>
    /// <typeparam name="TRoleClaim">The type of the class representing a role claim.</typeparam>
    public class ArangoRoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim> :
        IQueryableRoleStore<TRole>,
        IRoleClaimStore<TRole>
        where TRole : ArangoIdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TContext : IArangoDbContext
        where TUserRole : ArangoIdentityUserRole<TKey>, new()
        where TRoleClaim: IdentityRoleClaim<TKey>, new()
    {
        protected IQueryable<ArangoIdentityRole> roleCollection;

        /// <summary>
        /// Constructs a new instance of <see cref="ArangoRoleStore{TRole, TContext, TKey, TUserRole, TRoleClaim}"/>.
        /// </summary>
        /// <param name="context">The <see cref="IArangoDbContext"/>.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public ArangoRoleStore(IArangoDbContext context, IdentityErrorDescriber describer = null)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
            initRoleCollection().Wait();
        }

        private async Task initRoleCollection()
        {
            var cts = await Context.Client.Cursor.PostCursorAsync<ArangoIdentityRole>(
                $"for r in {Constants.ROLE_COLLECTION} return r");

            roleCollection = cts.Result.AsQueryable();
        }

        /// <summary>
        /// A navigation property for the roles the store contains.
        /// </summary>
        public virtual IQueryable<TRole> Roles => roleCollection as IQueryable<TRole>;

        /// <summary>
        /// Gets or sets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        private bool _disposed;
        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        private static IArangoDbContext Context { get; set; }

        private static IArangoDbRepository _ArangoRepository;
        private static IArangoDbRepository ArangoRepository => _ArangoRepository ??= new ArangoRepository(Context);

        /// <summary>
        /// Gets or sets a flag indicating if changes should be persisted after CreateAsync, UpdateAsync and DeleteAsync are called.
        /// </summary>
        /// <value>
        /// True if changes should be automatically persisted, otherwise false.
        /// </value>
        public bool AutoSaveChanges { get; set; } = true;

        /// <summary>
        /// Creates a new role in a store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to create in the store.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        public virtual async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var r = role as ArangoIdentityRole;
            if (r == null) return IdentityResult.Failed();

            var ret = await Context.Client.Document.PostDocumentAsync(Constants.ROLE_COLLECTION, r);

            r._id = ret._id;
            r.Id = ret._id;
            r._key = ret._key;
            r._rev = ret._rev;

            return IdentityResult.Success;
        }

        /// <summary>
        /// Updates a role in a store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to update in the store.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        /// <remarks>Uses the ArangoDb revision ID for the concurrency stamp.</remarks>
        public virtual async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var r = role as ArangoIdentityRole;
            if (r == null) return IdentityResult.Failed(new IdentityError {Description = "could not convert role to ArangoIdentityRole"});

            var ret = await Context.Client.Document.PutDocumentAsync(r._id, r);
            r._rev = ret._rev;
            r.ConcurrencyStamp = ret._rev;

            return IdentityResult.Success;
        }


        /// <summary>
        /// Deletes a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to delete from the store.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        public virtual async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var r = role as ArangoIdentityRole;

            var d1 = $"for u in {Constants.USER_ROLE_EDGE} filter u._to == '{r._id}' remove "
                     + "{_key: r._key} " + $"from {Constants.USER_ROLE_EDGE}";

            await Context.Client.Cursor.PostCursorAsync<string>(d1);
            var ret = await Context.Client.Document.DeleteDocumentAsync<string>("Roles", r._key);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Gets the ID for a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose ID should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications
        /// that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the ID of the role.</returns>
        public virtual Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var r = role as ArangoIdentityRole;
            if (r == null) throw new ArgumentException("Role does not convert to ArangoIdentityRole");
            return Task.FromResult(r._id);
        }

        /// <summary>
        /// Gets the name of a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose name should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        public virtual Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.Name);
        }

        /// <summary>
        /// Sets the name of a role in the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose name should be set.</param>
        /// <param name="roleName">The name of the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual async Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (role.Name != roleName)
            {
                role.Name = roleName;
                var r = role as ArangoIdentityRole;
                if (r == null) throw new ArgumentException("Role does not convert to ArangoIdentityRole");
                await Context.Client.Document.PutDocumentAsync<ArangoIdentityRole>(r._id, r);
            }
        }

        /// <summary>
        /// Converts the provided <paramref name="id"/> to a strongly typed key object.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided <paramref name="id"/>.</returns>
        public virtual TKey ConvertIdFromString(string id)
        {
            return id.ToTKey<TKey>();
        }

        /// <summary>
        /// Converts the provided <paramref name="id"/> to its string representation.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="string"/> representation of the provided <paramref name="id"/>.</returns>
        public virtual string ConvertIdToString(TKey id)
        {
            if (id == null)
            {
                return null;
            }

            return id.Equals(default(TKey)) ? null : id.ToString();
        }

        /// <summary>
        /// Finds the role who has the specified ID as an asynchronous operation.
        /// </summary>
        /// <param name="id">The role ID to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        public virtual async Task<TRole> FindByIdAsync(string id, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var q = $"for r in Roles filter r._id == '{id}' return r";
            var ret = await Context.Client.Cursor.PostCursorAsync<ArangoIdentityRole>(q);
            return ret.Result.First() as TRole;
        }

        /// <summary>
        /// Finds the role who has the specified normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="normalizedName">The normalized role name to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        public virtual async Task<TRole> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var q = $"for r in Roles filter r.NormalizedName == '{normalizedName}' return r";
            var ret = await Context.Client.Cursor.PostCursorAsync<ArangoIdentityRole>(q);
            return ret.Result.First() as TRole;
        }

        /// <summary>
        /// Get a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        public virtual Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.NormalizedName);
        }

        /// <summary>
        /// Set a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be set.</param>
        /// <param name="normalizedName">The normalized name to set</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual async Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (role.NormalizedName != normalizedName)
            {
                var q = $"for r in Roles filter r.Name == '{role.NormalizedName}'" +
                        "update {_key: r._key, NormalizedName: '" + normalizedName + "'} in Roles";
                var ret = await Context.Client.Cursor.PostCursorAsync<string>(q);
            }
        }

        /// <summary>
        /// Throws if this class has been disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        /// Dispose the stores
        /// </summary>
        public void Dispose() => _disposed = true;


#pragma warning disable CS1998
                              /// <summary>
                              /// Get the claims associated with the specified <paramref name="role"/> as an asynchronous operation.
                              /// </summary>
                              /// <param name="role">The role whose claims should be retrieved.</param>
                              /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
                              /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a role.</returns>
        public virtual async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
#pragma warning restore CS1998
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return role.Claims.Select(e => e.ToClaim()).ToList();
        }

        /// <summary>
        /// Adds the <paramref name="claim"/> given to the specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The role to add the claim to.</param>
        /// <param name="claim">The claim to add to the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (role.AddClaim(claim))
            {
                var ret = await Context.Client.Document.PostDocumentAsync(Constants.CLAIMS_COLLECTION, claim);
                var edge = new EdgeRecord
                {
                    _from = role._id,
                    _to = ret._id
                };

                var r = await Context.Client.Document.PostDocumentAsync(Constants.USER_ROLE_CLAIMS_EDGE, edge);

            }
        }

        /// <summary>
        /// Removes the <paramref name="claim"/> given from the specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The role to remove the claim from.</param>
        /// <param name="claim">The claim to remove from the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            // TODO: this query is no good -- we'll need to refactor where we look up the claim ID in Claims, reference it in UserRoleClaims, and delete
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (role.RemoveClaim(claim))
            {
                var q = $"for r in {Constants.USER_ROLE_CLAIMS_EDGE} filter r._from == '{role._id}' " +
                        "remove {_key: r._key} in " + Constants.USER_ROLE_CLAIMS_EDGE;
                var ret = await Context.Client.Cursor.PostCursorAsync<string>(q);

                var r = $"for c in {Constants.CLAIMS_COLLECTION} filter c.Issuer == '{claim.Issuer}' "
                        +  $"filter c.OriginalIssuer == '{claim.OriginalIssuer}' " +
                        $"filter c.Value == '{claim.Value}' filter c.Type == '{claim.Type}' remove " +
                        "{_key: c._key} in " + Constants.CLAIMS_COLLECTION;
                ret = await Context.Client.Cursor.PostCursorAsync<string>(r);
            }
        }



        /// <summary>
        /// Creates a entity representing a role claim.
        /// </summary>
        /// <param name="role">The associated role.</param>
        /// <param name="claim">The associated claim.</param>
        /// <returns>The role claim entity.</returns>
        protected virtual TRoleClaim CreateRoleClaim(TRole role, Claim claim)
            => new TRoleClaim { RoleId = role.Id, ClaimType = claim.Type, ClaimValue = claim.Value };

    }
}
