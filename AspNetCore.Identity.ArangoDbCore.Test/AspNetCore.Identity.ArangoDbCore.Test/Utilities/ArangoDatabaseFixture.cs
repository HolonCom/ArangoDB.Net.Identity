using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using AspNetCore.Identity.ArangoDbCore.Models;
using AspNetCore.Identity.ArangoDbCore.Test.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;

namespace AspNetCore.Identity.ArangoDbCore.Test.AspNetCore.Identity.ArangoDbCore.Test.Utilities
{
    public class ArangoDatabaseFixture<TUser, TKey>: IDisposable
        where TUser : ArangoIdentityUser
        where TKey : IEquatable<TKey>
    {
        public IArangoDbContext Context;

        public ArangoDatabaseFixture()
        {
            Context = new ArangoDbContext(Container.Settings);
            UsersToDelete = new ConcurrentBag<TUser>();
        }

        public ConcurrentBag<TUser> UsersToDelete { get; set; }

        public void Dispose()
        {
            DisposeUsers(UsersToDelete.ToList().Select(e => e.Id)).Wait();

        }

        public async Task DisposeUserRoles(IEnumerable<string> roleIds)
        {
            var sb = new StringBuilder();
            sb.Append($"for u in {Constants.ROLE_COLLECTION}");
            foreach (var id in roleIds)
            {
                sb.AppendLine($"filter u._id == '{id}'");
            }

            sb.AppendLine("remove {_id: u._id } in " + Constants.ROLE_COLLECTION);

            await Context.Client.Cursor.PostCursorAsync<string>(sb.ToString());
        }

        /// <summary>
        /// Delete users from both User collection and User Role edge.
        /// </summary>
        /// <param name="userIds">The user IDs to delete.</param>
        /// <returns></returns>
        public async Task DisposeUsers(IEnumerable<string> userIds)
        {
            var userDelete = new StringBuilder();
            userDelete.Append("for u in Users");
            var idList = userIds.ToList();

            foreach (var id in idList)
            {
                userDelete.AppendLine($"filter u._id == '{id}'");
            }
            userDelete.AppendLine("remove {_id: u._id } in Users");

            var userRoleDelete = new StringBuilder();
            userRoleDelete.Append($"for ur in {Constants.USER_ROLE_EDGE}");
            foreach (var id in idList)
            {
                userRoleDelete.AppendLine($"filter u._from == '{id}'");
            }

            userRoleDelete.Append("remove {_from: u._from } in " + Constants.USER_ROLE_EDGE);
            await Context.Client.Cursor.PostCursorAsync<string>(userDelete.ToString());
            await Context.Client.Cursor.PostCursorAsync<string>(userRoleDelete.ToString());
        }
    }

    public class ArangoDatabaseFixture<TUser, TRole, TKey> : ArangoDatabaseFixture<TUser, TKey>, IDisposable
        where TUser : ArangoIdentityUser
        where TRole : ArangoIdentityRole
        where TKey : IEquatable<TKey>
    {
        public ArangoDatabaseFixture()
        {
            Context = new ArangoDbContext(Container.Settings);
            UsersToDelete = new ConcurrentBag<TUser>();
            RolesToDelete = new ConcurrentBag<TRole>();
        }
        public ConcurrentBag<TRole> RolesToDelete { get; set; }

        public new void Dispose()
        {
            var userIds = UsersToDelete.ToList().Select(e => e.Id);
            var idList = userIds.ToList();
            if (idList.Any())
            {
                DisposeUsers(idList).Wait();
            }
            var roleIds = RolesToDelete.ToList().Select(e => e.Id).ToList();
            if (roleIds.Any())
            {
                DisposeUserRoles(roleIds).Wait();
            }
        }

    }
}
