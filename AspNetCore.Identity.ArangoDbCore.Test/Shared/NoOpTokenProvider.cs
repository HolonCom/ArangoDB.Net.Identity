using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    public class NoOpTokenProvider : IUserTwoFactorTokenProvider<TestUser>
    {
        public string Name { get; } = "Noop";

        public Task<string> GenerateAsync(string purpose, UserManager<TestUser> manager, TestUser user)
        {
            return Task.FromResult("Test");
        }

        public Task<bool> ValidateAsync(string purpose, string token, UserManager<TestUser> manager, TestUser user)
        {
            return Task.FromResult(true);
        }

        public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TestUser> manager, TestUser user)
        {
            return Task.FromResult(true);
        }
    }

}
