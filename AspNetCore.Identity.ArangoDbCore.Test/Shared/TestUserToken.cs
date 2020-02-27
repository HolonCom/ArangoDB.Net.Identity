namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    public class TestUserToken
    {
        /// <summary>
        ///     The login provider for the login (i.e. facebook, google)
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        ///     Key representing the login for the provider
        /// </summary>
        public virtual string TokenName { get; set; }

        /// <summary>
        ///     Display name for the login
        /// </summary>
        public virtual string TokenValue { get; set; }

        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        public virtual string UserId { get; set; }
    }
}
