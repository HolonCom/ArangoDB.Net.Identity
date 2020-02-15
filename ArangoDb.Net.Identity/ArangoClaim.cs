namespace ArangoDb.Net.Identity
{
    /// <summary>
    /// A class representing the claims a <see cref="ArangoIdentityUser{TKey}"/> can have.
    /// </summary>
    public class ArangoClaim
    {
        /// <summary>
        /// The type of the claim.
        /// </summary>
        public string Type { get; set; }
        /// <summary>
        /// The value of the claim.
        /// </summary>
        public string Value { get; set; }
        /// <summary>
        /// The issuer of the claim.
        /// </summary>
        public string Issuer { get; set; }
    }
}
