namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    public class TestUserRole
    {
        /// <summary>
        ///     UserId for the user that is in the role
        /// </summary>
        public virtual string UserId { get; set; }

        /// <summary>
        ///     RoleId for the role
        /// </summary>
        public virtual string RoleId { get; set; }

    }
}
