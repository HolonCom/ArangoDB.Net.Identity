using System;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Extensions;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using AspNetCore.Identity.ArangoDbCore.Models;
using AspNetCore.Identity.ArangoDbCore.Test.AspNetCore.Identity.ArangoDbCore.Test.Utilities;
using AspNetCore.Identity.ArangoDbCore.Test.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Test.Specification;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AspNetCore.Identity.ArangoDbCore.Test.AspNetCore.Identity.ArangoDbCore.Test
{
    public abstract class ArangoDbStoreTestBase<TUser, TRole, TKey> : IdentitySpecificationTestBase<TUser, TRole, TKey>,
        IClassFixture<ArangoDatabaseFixture<TUser, TRole, TKey>>
        where TUser : ArangoIdentityUser, new()
        where TRole : ArangoIdentityRole, new()
        where TKey : IEquatable<TKey>
    {
        private readonly ArangoDatabaseFixture<TUser, TRole, TKey> _fixture;

        protected ArangoDbStoreTestBase(ArangoDatabaseFixture<TUser, TRole, TKey> fixture)
        {
            _fixture = fixture;
        }

        protected override void SetupIdentityServices(IServiceCollection services)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            // configure the default type name
            services.ConfigureArangoDbIdentity<TUser, TRole, TKey>(Container.ArangoDbIdentityConfiguration, Container.ArangoRepository.Context);

            services.AddLogging();
            services.AddSingleton<ILogger<UserManager<TUser>>>(new TestLogger<UserManager<TUser>>());
            services.AddSingleton<ILogger<RoleManager<TRole>>>(new TestLogger<RoleManager<TRole>>());
        }

        protected override bool ShouldSkipDbTests()
        {
            return false;
        }

        protected override TUser CreateTestUser(string namePrefix = "", string email = "", string phoneNumber = "",
            bool lockoutEnabled = false, DateTimeOffset? lockoutEnd = null, bool useNamePrefixAsUserName = false)
        {
            var user = new TUser
            {
                UserName = useNamePrefixAsUserName ? namePrefix : $"{namePrefix}{Guid.NewGuid()}",
                Email = email,
                PhoneNumber = phoneNumber,
                LockoutEnabled = lockoutEnabled,
                LockoutEnd = lockoutEnd
            };
            _fixture.UsersToDelete.Add(user);
            return user;
        }

        protected override TRole CreateTestRole(string roleNamePrefix = "", bool useRoleNamePrefixAsRoleName = false)
        {
            var roleName = useRoleNamePrefixAsRoleName ? roleNamePrefix : $"{roleNamePrefix}{Guid.NewGuid()}";
            var role = new TRole() { Name = roleName };
            _fixture.RolesToDelete.Add(role);
            return role;
        }

        protected override Expression<Func<TRole, bool>> RoleNameEqualsPredicate(string roleName) => r => r.Name == roleName;

        protected override Expression<Func<TUser, bool>> UserNameEqualsPredicate(string userName) => u => u.UserName == userName;


        protected override Expression<Func<TRole, bool>> RoleNameStartsWithPredicate(string roleName) => r => r.Name.StartsWith(roleName);

        protected override Expression<Func<TUser, bool>> UserNameStartsWithPredicate(string userName) => u => u.UserName.StartsWith(userName);


        protected override void AddUserStore(IServiceCollection services, object context = null)
        {
            services.AddSingleton<IUserStore<TUser>>(new ArangoUserStore<TUser, TRole, IArangoDbContext>(Container.ArangoRepository.Context));
        }

        protected override void AddRoleStore(IServiceCollection services, object context = null)
        {
            services.AddSingleton<IRoleStore<TRole>>(new ArangoRoleStore<TRole, IArangoDbContext>(Container.ArangoRepository.Context));
        }

        protected override void SetUserPasswordHash(TUser user, string hashedPassword)
        {
            user.PasswordHash = hashedPassword;
        }

        [Fact]
        public async Task DeleteRoleNonEmptySucceedsTest()
        {
            var userMgr = CreateManager();
            var roleMgr = CreateRoleManager();
            var roleName = "delete" + Guid.NewGuid().ToString();
            var role = CreateTestRole(roleName, useRoleNamePrefixAsRoleName: true);
            Assert.False(await roleMgr.RoleExistsAsync(roleName));
            IdentityResultAssert.IsSuccess(await roleMgr.CreateAsync(role));
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await userMgr.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await userMgr.AddToRoleAsync(user, roleName));
            var roles = await userMgr.GetRolesAsync(user);
            Assert.Single(roles);
            IdentityResultAssert.IsSuccess(await roleMgr.DeleteAsync(role));
            Assert.Null(await roleMgr.FindByNameAsync(roleName));
            Assert.False(await roleMgr.RoleExistsAsync(roleName));
            // REVIEW: We should throw if deleting a non empty role?
            roles = await userMgr.GetRolesAsync(user);

            Assert.Empty(roles);
        }
        [Fact]
        public async Task DeleteUserRemovesFromRoleTest()
        {
            // Need fail if not empty?
            var userMgr = CreateManager();
            var roleMgr = CreateRoleManager();
            var roleName = "deleteUserRemove" + Guid.NewGuid().ToString();
            var role = CreateTestRole(roleName, useRoleNamePrefixAsRoleName: true);
            Assert.False(await roleMgr.RoleExistsAsync(roleName));
            IdentityResultAssert.IsSuccess(await roleMgr.CreateAsync(role));
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await userMgr.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await userMgr.AddToRoleAsync(user, roleName));

            var roles = await userMgr.GetRolesAsync(user);
            Assert.Single(roles);

            IdentityResultAssert.IsSuccess(await userMgr.DeleteAsync(user));

            roles = await userMgr.GetRolesAsync(user);
            Assert.Empty(roles);
        }

        [Fact]
        public async Task DeleteUserRemovesTokensTest()
        {
            // Need fail if not empty?
            var userMgr = CreateManager();
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await userMgr.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await userMgr.SetAuthenticationTokenAsync(user, "provider", "test", "value"));

            Assert.Equal("value", await userMgr.GetAuthenticationTokenAsync(user, "provider", "test"));

            IdentityResultAssert.IsSuccess(await userMgr.DeleteAsync(user));

            Assert.Null(await userMgr.GetAuthenticationTokenAsync(user, "provider", "test"));
        }

        // private IQueryable<TUser> GetQueryable()
        // {
        //     return Container.ArangoRepository.Context.GetCollection<TUser>().AsQueryable();
        // }

        // [Fact]
        // public void CanCreateUserUsingEF()
        // {
        //     var user = CreateTestUser();
        //     Container.ArangoRepository.AddOne<TUser, TKey>(user);
        //     Assert.True(GetQueryable().Any(u => u.UserName == user.UserName));
        //     Assert.NotNull(GetQueryable().FirstOrDefault(u => u.UserName == user.UserName));
        // }

        [Fact]
        public async Task CanCreateUsingManager()
        {
            var manager = CreateManager();
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await manager.DeleteAsync(user));
        }

        private async Task LazyLoadTestSetup(TUser user)
        {
            var manager = CreateManager();
            var role = CreateRoleManager();
            var admin = CreateTestRole("Admin" + Guid.NewGuid());
            var local = CreateTestRole("Local" + Guid.NewGuid());
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            IdentityResultAssert.IsSuccess(await manager.AddLoginAsync(user, new UserLoginInfo("provider", user.Id, "display")));
            IdentityResultAssert.IsSuccess(await role.CreateAsync(admin));
            IdentityResultAssert.IsSuccess(await role.CreateAsync(local));
            IdentityResultAssert.IsSuccess(await manager.AddToRoleAsync(user, admin.Name));
            IdentityResultAssert.IsSuccess(await manager.AddToRoleAsync(user, local.Name));
            Claim[] userClaims =
            {
                new Claim("Whatever", "Value"),
                new Claim("Whatever2", "Value2")
            };
            foreach (var c in userClaims)
            {
                IdentityResultAssert.IsSuccess(await manager.AddClaimAsync(user, c));
            }
        }

        [Fact]
        public async Task LoadFromDbFindByIdTest()
        {
            var user = CreateTestUser();
            await LazyLoadTestSetup(user);

            var manager = CreateManager();

            var userById = await manager.FindByIdAsync(user.Id);
            Assert.Equal(2, (await manager.GetClaimsAsync(userById)).Count);
            Assert.Equal(1, (await manager.GetLoginsAsync(userById)).Count);
            Assert.Equal(2, (await manager.GetRolesAsync(userById)).Count);
        }

        [Fact]
        public async Task LoadFromDbFindByNameTest()
        {
            var user = CreateTestUser();
            await LazyLoadTestSetup(user);
            var manager = CreateManager();
            var userByName = await manager.FindByNameAsync(user.UserName);
            Assert.Equal(2, (await manager.GetClaimsAsync(userByName)).Count);
            Assert.Equal(1, (await manager.GetLoginsAsync(userByName)).Count);
            Assert.Equal(2, (await manager.GetRolesAsync(userByName)).Count);
        }

        [Fact]
        public async Task LoadFromDbFindByLoginTest()
        {
            var user = CreateTestUser();
            await LazyLoadTestSetup(user);

            var manager = CreateManager();
            var userByLogin = await manager.FindByLoginAsync("provider", user.Id);
            Assert.Equal(2, (await manager.GetClaimsAsync(userByLogin)).Count);
            Assert.Equal(1, (await manager.GetLoginsAsync(userByLogin)).Count);
            Assert.Equal(2, (await manager.GetRolesAsync(userByLogin)).Count);
        }

        [Fact]
        public async Task LoadFromDbFindByEmailTest()
        {
            var user = CreateTestUser();
            user.Email = "fooz@fizzy.pop";
            await LazyLoadTestSetup(user);

            var manager = CreateManager();
            var userByEmail = await manager.FindByEmailAsync(user.Email);
            Assert.Equal(2, (await manager.GetClaimsAsync(userByEmail)).Count);
            Assert.Equal(1, (await manager.GetLoginsAsync(userByEmail)).Count);
            Assert.Equal(2, (await manager.GetRolesAsync(userByEmail)).Count);
        }

    }
}
