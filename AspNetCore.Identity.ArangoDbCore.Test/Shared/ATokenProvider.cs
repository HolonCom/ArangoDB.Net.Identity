using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    public class ATokenProvider : IUserTwoFactorTokenProvider<TestUser>
    {
        public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TestUser> manager, TestUser user)
        {
            throw new NotImplementedException();
        }

        public Task<string> GenerateAsync(string purpose, UserManager<TestUser> manager, TestUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> ValidateAsync(string purpose, string token, UserManager<TestUser> manager, TestUser user)
        {
            throw new NotImplementedException();
        }
    }

}
