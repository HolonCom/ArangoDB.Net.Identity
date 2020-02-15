using System;
using Microsoft.AspNetCore.Identity;

namespace ArangoDb.Net.Identity
{
    public class ArangoIdentityUserRole: IdentityUserRole<string>
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
