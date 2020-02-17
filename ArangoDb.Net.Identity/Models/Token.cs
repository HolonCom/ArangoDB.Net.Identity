namespace ArangoDb.Net.Identity.Models
{
    /// <summary>
    /// A class representing the tokens an <see cref="ArangoIdentityUser{TKey}"/> can have.
    /// </summary>
    public class Token
    {
        /// <summary>
        /// Gets or sets the LoginProvider this token is from.
        /// </summary>
        public string LoginProvider { get; set; }
        /// <summary>
        /// Gets or sets the name of the token.
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// Gets or sets the token value.
        /// </summary>
        public string Value { get; set; }

    }
}
