using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Models
{
    public class ArangoIdentityRole<TKey> : IdentityRole<TKey>, IClaimHolder
        where TKey : IEquatable<TKey>
    {
        public string _id { get; set; }
        public string _key { get; set; }
        public string _rev { get; set; }

        public override TKey Id { get; set; }
        public List<ArangoClaim> Claims { get; set; }
    }

    public class ArangoIdentityRole : ArangoIdentityRole<string>
    {
        public ArangoIdentityRole()
        {
            //do not delete
        }
        public override string Id { get; set; }

    }
}
