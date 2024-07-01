using System;
using System.Linq.Expressions;
using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using AspNetCore.Identity.ArangoDbCore.Models;
using AspNetCore.Identity.ArangoDbCore.Stores;
using AspNetCore.Identity.ArangoDbCore.Test.AspNetCore.Identity.ArangoDbCore.Test.Utilities;
using AspNetCore.Identity.ArangoDbCore.Test.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Test.Specification;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AspNetCore.Identity.ArangoDbCore.Test.AspNetCore.Identity.ArangoDbCore.Test
{
    public class UserStoreTest: IdentitySpecificationTestBase<ArangoIdentityUser,ArangoIdentityRole>,
        IClassFixture<ArangoDatabaseFixture<ArangoIdentityUser,ArangoIdentityRole>>
    {

        public UserStoreTest(ArangoDatabaseFixture<ArangoIdentityUser, ArangoIdentityRole> databaseFixture)
        {
            fixture = databaseFixture;
        }

        private readonly ArangoDatabaseFixture<ArangoIdentityUser, ArangoIdentityRole> fixture;

        [Fact]
        public async Task CanCreateUserUsingArangoDB()
        {
            var user = CreateTestUser();
            var guidString = Guid.NewGuid().ToString();
            user.UserName = guidString;
            await Container.ArangoRepository.Context.Client.Document.PostDocumentAsync("Users", user);
            Assert.True(user.UserName == guidString);
            Assert.NotNull(user._id);
            Assert.Equal(user.Id,user._id);
            await Container.ArangoRepository.Context.Client.Document.DeleteDocumentAsync<ArangoIdentityUser>("Users",
                user._id);
        }

        protected override void AddUserStore(IServiceCollection services, object context = null)
        {
            services.AddSingleton<IUserStore<ArangoIdentityUser>>(new ArangoUserStore<ArangoIdentityUser, ArangoIdentityRole, IArangoDbContext>(
                Container.ArangoRepository.Context));
        }

        protected override void SetUserPasswordHash(ArangoIdentityUser user, string hashedPassword) =>
            user.PasswordHash = hashedPassword;

        protected override ArangoIdentityUser CreateTestUser(string namePrefix = "", string email = "", string phoneNumber = "",
            bool lockoutEnabled = false, DateTimeOffset? lockoutEnd = null, bool useNamePrefixAsUserName = false)
        {
            var user = new ArangoIdentityUser
            {
                UserName = useNamePrefixAsUserName ? namePrefix : $"{namePrefix}{Guid.NewGuid()}",
                Email = email,
                PhoneNumber = phoneNumber,
                LockoutEnabled = lockoutEnabled,
                LockoutEnd = lockoutEnd
            };
            fixture.UsersToDelete.Add(user);
            return user;
        }

        protected override Expression<Func<ArangoIdentityUser, bool>> UserNameEqualsPredicate(string userName) =>
            u => u.UserName == userName;

        protected override Expression<Func<ArangoIdentityUser, bool>> UserNameStartsWithPredicate(string userName) =>
        u => u.UserName.StartsWith(userName);

        protected override void AddRoleStore(IServiceCollection services, object context = null)
        {
            services.AddSingleton<IRoleStore<ArangoIdentityRole>>(
                new ArangoRoleStore<ArangoIdentityRole, ArangoDbContext>(Container.ArangoRepository.Context));
        }

        protected override ArangoIdentityRole CreateTestRole(string roleNamePrefix = "", bool useRoleNamePrefixAsRoleName = false)
        {
            var roleName = useRoleNamePrefixAsRoleName ? roleNamePrefix : $"{roleNamePrefix}{Guid.NewGuid()}";
            var role = new ArangoIdentityRole() {Name = roleName};
            return role;
        }

        protected override Expression<Func<ArangoIdentityRole, bool>> RoleNameEqualsPredicate(string roleName) =>
            r => r.Name.Equals(roleName);

        protected override Expression<Func<ArangoIdentityRole, bool>> RoleNameStartsWithPredicate(string roleName) =>
            r => r.Name.StartsWith(roleName);

        [Fact]
        public async Task SqlUserStoreMethodsThrowWhenDisposedTest()
        {
            var store = new ArangoUserStore(Container.ArangoRepository.Context);
            store.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.AddClaimsAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.AddLoginAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.AddToRoleAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.GetClaimsAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.GetLoginsAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.GetRolesAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.IsInRoleAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.RemoveClaimsAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.RemoveLoginAsync(null, null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.RemoveFromRoleAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.RemoveClaimsAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.ReplaceClaimAsync(null, null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.FindByLoginAsync(null, null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.FindByIdAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.FindByNameAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.CreateAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.UpdateAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.DeleteAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.SetEmailConfirmedAsync(null, true));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await store.GetEmailConfirmedAsync(null));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.SetPhoneNumberConfirmedAsync(null, true));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.GetPhoneNumberConfirmedAsync(null));
        }
        [Fact]
        public async Task UserStorePublicNullCheckTest()
        {
            Assert.Throws<ArgumentNullException>("context", () => new ArangoUserStore(null));
            var store = new ArangoUserStore(Container.ArangoRepository.Context);
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetUserIdAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetUserNameAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.SetUserNameAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.CreateAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.UpdateAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.DeleteAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.AddClaimsAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.ReplaceClaimAsync(null, null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.RemoveClaimsAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetClaimsAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetLoginsAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetRolesAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.AddLoginAsync(null, null));
            await
                Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.RemoveLoginAsync(null, null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.AddToRoleAsync(null, null));
            await
                Assert.ThrowsAsync<ArgumentNullException>("user",
                    async () => await store.RemoveFromRoleAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.IsInRoleAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetPasswordHashAsync(null));
            await
                Assert.ThrowsAsync<ArgumentNullException>("user",
                    async () => await store.SetPasswordHashAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetSecurityStampAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user",
                async () => await store.SetSecurityStampAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("login", async () => await store.AddLoginAsync(new ArangoIdentityUser("fake"), null));
            await Assert.ThrowsAsync<ArgumentNullException>("claims",
                async () => await store.AddClaimsAsync(new ArangoIdentityUser("fake"), null));
            await Assert.ThrowsAsync<ArgumentNullException>("claims",
                async () => await store.RemoveClaimsAsync(new ArangoIdentityUser("fake"), null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetEmailConfirmedAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user",
                async () => await store.SetEmailConfirmedAsync(null, true));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetEmailAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.SetEmailAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetPhoneNumberAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.SetPhoneNumberAsync(null, null));
            await Assert.ThrowsAsync<ArgumentNullException>("user",
                async () => await store.GetPhoneNumberConfirmedAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user",
                async () => await store.SetPhoneNumberConfirmedAsync(null, true));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetTwoFactorEnabledAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user",
                async () => await store.SetTwoFactorEnabledAsync(null, true));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetAccessFailedCountAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetLockoutEnabledAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.SetLockoutEnabledAsync(null, false));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.GetLockoutEndDateAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.SetLockoutEndDateAsync(null, new DateTimeOffset()));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.ResetAccessFailedCountAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>("user", async () => await store.IncrementAccessFailedCountAsync(null));
            await Assert.ThrowsAsync<ArgumentException>("normalizedRoleName", async () => await store.AddToRoleAsync(new ArangoIdentityUser("fake"), null));
            await Assert.ThrowsAsync<ArgumentException>("normalizedRoleName", async () => await store.RemoveFromRoleAsync(new ArangoIdentityUser("fake"), null));
            await Assert.ThrowsAsync<ArgumentException>("normalizedRoleName", async () => await store.IsInRoleAsync(new ArangoIdentityUser("fake"), null));
            await Assert.ThrowsAsync<ArgumentException>("normalizedRoleName", async () => await store.AddToRoleAsync(new ArangoIdentityUser("fake"), ""));
            await Assert.ThrowsAsync<ArgumentException>("normalizedRoleName", async () => await store.RemoveFromRoleAsync(new ArangoIdentityUser("fake"), ""));
            await Assert.ThrowsAsync<ArgumentException>("normalizedRoleName", async () => await store.IsInRoleAsync(new ArangoIdentityUser("fake"), ""));
        }

        [Fact]
        public async Task CanCreateUsingManager()
        {
            var manager = CreateManager();
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await manager.DeleteAsync(user));
        }

        [Fact]
        public async Task TwoUsersSamePasswordDifferentHash()
        {
            var manager = CreateManager();
            var userA = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(userA, "password"));
            var userB = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(userB, "password"));

            Assert.NotEqual(userA.PasswordHash, userB.PasswordHash);
        }
        [Fact]
        public async Task AddUserToUnknownRoleFails()
        {
            var manager = CreateManager();
            var u = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(u));
            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await manager.AddToRoleAsync(u, "bogus"));
        }

        [Fact]
        public async Task ConcurrentUpdatesWillFail()
        {
            var user = CreateTestUser();
            var manager = CreateManager();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            var manager1 = CreateManager();
            var manager2 = CreateManager();
            var user1 = await manager1.FindByIdAsync(user.Id);
            var user2 = await manager2.FindByIdAsync(user.Id);
            Assert.NotNull(user1);
            Assert.NotNull(user2);
            Assert.NotSame(user1, user2);
            user1.UserName = Guid.NewGuid().ToString();
            user2.UserName = Guid.NewGuid().ToString();
            IdentityResultAssert.IsSuccess(await manager1.UpdateAsync(user1));
            IdentityResultAssert.IsFailure(await manager2.UpdateAsync(user2), new IdentityErrorDescriber().ConcurrencyFailure());
        }

        [Fact]
        public async Task ConcurrentUpdatesWillFailWithDetachedUser()
        {
            var user = CreateTestUser();
            var manager = CreateManager();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            var manager1 = CreateManager();
            var manager2 = CreateManager();
            var user2 = await manager2.FindByIdAsync(user.Id);
            Assert.NotNull(user2);
            Assert.NotSame(user, user2);
            user.UserName = Guid.NewGuid().ToString();
            user2.UserName = Guid.NewGuid().ToString();
            IdentityResultAssert.IsSuccess(await manager1.UpdateAsync(user));
            IdentityResultAssert.IsFailure(await manager2.UpdateAsync(user2), new IdentityErrorDescriber().ConcurrencyFailure());
        }


        [Fact]
        public async Task DeleteAModifiedUserWillFail()
        {
            var user = CreateTestUser();

            var manager = CreateManager();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));

            var manager1 = CreateManager();
            var manager2 = CreateManager();
            var user1 = await manager1.FindByIdAsync(user.Id);
            var user2 = await manager2.FindByIdAsync(user.Id);
            Assert.NotNull(user1);
            Assert.NotNull(user2);
            Assert.NotSame(user1, user2);
            user1.UserName = Guid.NewGuid().ToString();
            IdentityResultAssert.IsSuccess(await manager1.UpdateAsync(user1));
            IdentityResultAssert.IsFailure(await manager2.DeleteAsync(user2), new IdentityErrorDescriber().ConcurrencyFailure());
        }

        [Fact]
        public async Task ConcurrentRoleUpdatesWillFail()
        {
            var role = CreateRole();

            var manager = CreateRoleManager();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(role));

            var manager1 = CreateRoleManager();
            var manager2 = CreateRoleManager();
            var role1 = await manager1.FindByIdAsync(role.Id);
            var role2 = await manager2.FindByIdAsync(role.Id);
            Assert.NotNull(role1);
            Assert.NotNull(role2);
            Assert.NotSame(role1, role2);
            role1.Name = Guid.NewGuid().ToString();
            role2.Name = Guid.NewGuid().ToString();
            IdentityResultAssert.IsSuccess(await manager1.UpdateAsync(role1));
            IdentityResultAssert.IsFailure(await manager2.UpdateAsync(role2), new IdentityErrorDescriber().ConcurrencyFailure());
        }

        [Fact]
        public async Task ConcurrentRoleUpdatesWillFailWithDetachedRole()
        {
            var role = CreateRole();
            var manager = CreateRoleManager();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(role));
            var manager1 = CreateRoleManager();
            var manager2 = CreateRoleManager();
            var role2 = await manager2.FindByIdAsync(role.Id);
            Assert.NotNull(role);
            Assert.NotNull(role2);
            Assert.NotSame(role, role2);
            role.Name = Guid.NewGuid().ToString();
            role2.Name = Guid.NewGuid().ToString();
            IdentityResultAssert.IsSuccess(await manager1.UpdateAsync(role));
            IdentityResultAssert.IsFailure(await manager2.UpdateAsync(role2), new IdentityErrorDescriber().ConcurrencyFailure());
        }

        private ArangoIdentityRole CreateRole()
        {
            var role = new ArangoIdentityRole();
            fixture.RolesToDelete.Add(role);
            return role;
        }

        [Fact]
        public async Task DeleteAModifiedRoleWillFail()
        {
            var role = CreateRole();
            var manager = CreateRoleManager();
            var result = await manager.CreateAsync(role);

            IdentityResultAssert.IsSuccess(result);

            var manager1 = CreateRoleManager();
            var manager2 = CreateRoleManager(true);
            var role1 = await manager1.FindByIdAsync(role.Id);
            var role2 = await manager2.FindByIdAsync(role.Id);
            Assert.NotNull(role1);
            Assert.NotNull(role2);
            Assert.NotSame(role1, role2);
            role1.Name = Guid.NewGuid().ToString();
            IdentityResultAssert.IsSuccess(await manager1.UpdateAsync(role1));
            IdentityResultAssert.IsFailure(await manager2.DeleteAsync(role2), new IdentityErrorDescriber().ConcurrencyFailure());
        }


    }
}
