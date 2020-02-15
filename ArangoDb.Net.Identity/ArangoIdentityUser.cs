using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace ArangoDb.Net.Identity
{

/// <summary>
    /// A document representing an <see cref="IdentityUser{TKey}"/> document.
    /// </summary>
    /// <typeparam name="TKey">The type of the primary key.</typeparam>
    /// <remarks>We're only using the string value we get from the <c>_id</c> of the record in ArangoDB.</remarks>
    public class ArangoIdentityUser<TKey> : IdentityUser<TKey>, IClaimHolder
        where TKey : IEquatable<TKey>
    {
        public override TKey Id { get; set; }
        public List<ArangoClaim> Claims { get; set; }

        /// <summary>
        /// The ArangoDB identity. Do not alter.
        /// </summary>
        public string _id { get; set; }
        /// <summary>
        /// The ArangoDB key. Do not alter.
        /// </summary>
        public string _key { get; set; }
        /// <summary>
        /// The ArangoDB revision ID. Do not alter.
        /// </summary>
        public string _rev { get; set; }
    }

    /// <summary>
    /// See <see cref="ArangoIdentityUser{TKey}"/> where TKey is a <see cref="string"/>
    /// </summary>
    public class ArangoIdentityUser : ArangoIdentityUser<string>
    {
        public override string Id { get; set; }

    }
}
