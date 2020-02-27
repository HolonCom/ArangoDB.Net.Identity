using System;
using System.Collections.Generic;

namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    /// <summary>
    ///     Represents a Role entity
    /// </summary>
    public class TestRole
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        public TestRole() { }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="roleName"></param>
        public TestRole(string roleName) : this()
        {
            Name = roleName;
        }

        /// <summary>
        ///     Role id
        /// </summary>
        public virtual string Id { get; set; }

        /// <summary>
        /// Navigation property for claims in the role
        /// </summary>
        public virtual ICollection<TestRoleClaim> Claims { get; private set; } = new List<TestRoleClaim>();

        /// <summary>
        ///     Role name
        /// </summary>
        public virtual string Name { get; set; }

        /// <summary>
        /// Normalized name used for equality
        /// </summary>
        public virtual string NormalizedName { get; set; }

        /// <summary>
        /// A random value that should change whenever a role is persisted to the store
        /// </summary>
        public virtual string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    }
}
