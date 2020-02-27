using System;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore
{
    public class ArangoIdentityUserRole<TKey>: IdentityUserRole<TKey>
    where TKey: IEquatable<TKey>
    {
        /// <summary>
        /// The user ID. Do not alter.
        /// </summary>
        public string _from { get; set; }
        /// <summary>
        /// The role ID. Do not alter.
        /// </summary>
        public string _to { get; set; }
    }
}
