namespace AspNetCore.Identity.ArangoDbCore
{
    public static class Constants
    {
        public const string USER_COLLECTION = "Users";
        public const string ROLE_COLLECTION = "Roles";
        public const string CLAIMS_COLLECTION = "Claims";
        public const string USER_ROLE_EDGE = "UserRoles";
        public const string USER_LOGIN_INFO_EDGE = "UserLoginInfo";
        public const string USER_CLAIMS_EDGE = "UserClaims";
        public const string USER_ROLE_CLAIMS_EDGE = "UserRoleClaims";
    }
}
