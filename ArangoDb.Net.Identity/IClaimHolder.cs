using System.Collections.Generic;

namespace ArangoDb.Net.Identity
{
    /// <summary>
    /// The interface for an object that holds claims.
    /// </summary>
    public interface IClaimHolder
    {
        /// <summary>
        /// The claims the <see cref="IClaimHolder"/> has.
        /// </summary>
        List<ArangoClaim> Claims { get; set; }
    }
}
