using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Models
{
    /// <summary>
    /// ArangoDB implementation of <see cref="UserLoginInfo"/>.
    /// </summary>
    public class ArangoUserLoginInfo: UserLoginInfo
    {
        public ArangoUserLoginInfo(string loginProvider, string providerKey, string displayName) : base(loginProvider, providerKey, displayName)
        {
        }

        public string _from { get; set; }
        public string _to { get; set; }
    }
}
