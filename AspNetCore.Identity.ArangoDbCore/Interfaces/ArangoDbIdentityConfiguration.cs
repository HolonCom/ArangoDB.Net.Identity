using System;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Identity.ArangoDbCore.Interfaces
{
    /// <summary>
    /// A class used to perform a full configuration of the AspNetCore.Identity.ArangoDbCore package.
    /// </summary>
    public class ArangoDbIdentityConfiguration
    {

        /// <summary>
        /// The settings for the ArangoDb server.
        /// </summary>
        public ArangoDbSettings ArangoDbSettings { get; set; }

        /// <summary>
        /// An action against an <see cref="IdentityOptions"/> to change the default identity settings.
        /// </summary>
        public Action<IdentityOptions> IdentityOptionsAction { get; set; }

    }
}
