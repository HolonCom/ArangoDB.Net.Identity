using System;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Models
{
    public class ArangoIdentityRoleClaim<TKey>: IdentityRoleClaim<TKey>
    where TKey: IEquatable<TKey>
    {
        public string _id { get; set; }
        public string _key { get; set; }
        public string _rev { get; set; }
    }

    public class ArangoIdentityRoleClaim : ArangoIdentityRoleClaim<string>
    {
        public ArangoIdentityRoleClaim()
        {
            //do not delete
        }
    }
}
