using System;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore
{
    /// <summary>
    /// Represents a login and its associated provider for a user.
    /// </summary>
    public class ArangoIdentityUserLogin<TKey>:
        IdentityUserLogin<TKey> where TKey : IEquatable<TKey>
    {
        public string _id { get; set; }

        public string _rev { get; set; }

        public string _key { get; set; }

        public override string ProviderKey { get; set; }
        public override TKey UserId { get; set; }
        public override string LoginProvider { get; set; }
        public override string ProviderDisplayName { get; set; }
    }
}
