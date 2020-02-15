using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace ArangoDb.Net.Identity
{
    public class ArangoIdentityRole<TKey> : IdentityRole<TKey>, IClaimHolder
        where TKey : IEquatable<TKey>
    {
        public override TKey Id { get; set; }

        public List<ArangoClaim> Claims { get; set; }
    }

    public class ArangoIdentityRole : ArangoIdentityRole<string>
    {
        public string _id { get; set; }
    }
}
