using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Test.Shared;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace AspNetCore.Identity.ArangoDbCore.Test.AspNetCore.Identity.Test
{
    public class IdentityBuilderTest
    {
        [Fact]
        public void CanOverrideUserStore()
        {
            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
            services.AddIdentity<TestUser,TestRole>().AddUserStore<MyUberThingy>();
            var thingy = services.BuildServiceProvider().GetRequiredService<IUserStore<TestUser>>() as MyUberThingy;
            Assert.NotNull(thingy);
        }

        [Fact]
        public void CanOverrideRoleStore()
        {
            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
            services.AddIdentity<TestUser,TestRole>().AddRoleStore<MyUberThingy>();
            var thingy = services.BuildServiceProvider().GetRequiredService<IRoleStore<TestRole>>() as MyUberThingy;
            Assert.NotNull(thingy);
        }



        private class MyUberThingy : IUserValidator<TestUser>, IPasswordValidator<TestUser>,
            IRoleValidator<TestRole>, IUserStore<TestUser>, IRoleStore<TestRole>
        {
            public Task<IdentityResult> CreateAsync(TestRole role, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> DeleteAsync(TestRole role, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public void Dispose()
            {
                throw new NotImplementedException();
            }

            public Task<TestUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<TestUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<string> GetNormalizedRoleNameAsync(TestRole role, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<string> GetNormalizedUserNameAsync(TestUser user, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<string> GetRoleIdAsync(TestRole role, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<string> GetRoleNameAsync(TestRole role, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<string> GetUserNameAsync(TestUser user, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task SetNormalizedRoleNameAsync(TestRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task SetNormalizedUserNameAsync(TestUser user, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task SetRoleNameAsync(TestRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task SetUserNameAsync(TestUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> UpdateAsync(TestRole role, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken cancellationToken = default(CancellationToken))
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> ValidateAsync(RoleManager<TestRole> manager, TestRole role)
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> ValidateAsync(UserManager<TestUser> manager, TestUser user)
            {
                throw new NotImplementedException();
            }

            public Task<IdentityResult> ValidateAsync(UserManager<TestUser> manager, TestUser user, string password)
            {
                throw new NotImplementedException();
            }

            Task<TestRole> IRoleStore<TestRole>.FindByIdAsync(string roleId, CancellationToken cancellationToken)
            {
                throw new NotImplementedException();
            }

            Task<TestRole> IRoleStore<TestRole>.FindByNameAsync(string roleName, CancellationToken cancellationToken)
            {
                throw new NotImplementedException();
            }
        }
        private class MySignInManager : SignInManager<TestUser>
        {
            public MySignInManager(UserManager<TestUser> manager, IHttpContextAccessor context, IUserClaimsPrincipalFactory<TestUser> claimsFactory) :
                base(manager, context, claimsFactory, null, null, null) { }
        }

        private class MyUserManager : UserManager<TestUser>
        {
            public MyUserManager(IUserStore<TestUser> store) : base(store, null, null, null, null, null, null, null, null) { }
        }

        private class MyClaimsPrincipalFactory : UserClaimsPrincipalFactory<TestUser, TestRole>
        {
            public MyClaimsPrincipalFactory(UserManager<TestUser> userManager, RoleManager<TestRole> roleManager, IOptions<IdentityOptions> optionsAccessor) : base(userManager, roleManager, optionsAccessor)
            {
            }
        }

        private class MyRoleManager : RoleManager<TestRole>
        {
            public MyRoleManager(IRoleStore<TestRole> store,
                IEnumerable<IRoleValidator<TestRole>> roleValidators) : base(store, null, null, null, null)
            {

            }
        }
    }
}
