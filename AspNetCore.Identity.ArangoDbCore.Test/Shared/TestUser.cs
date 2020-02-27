using System;
using System.Collections.Generic;

namespace AspNetCore.Identity.ArangoDbCore.Test.Shared
{
    public class TestUser
    {
        /// <summary>
        /// ctor
        /// </summary>
        public TestUser() { }

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="userName"></param>
        public TestUser(string userName)
        {
            UserName = userName;
        }

        /// <summary>
        /// Id
        /// </summary>
        public virtual string Id { get; set; }

        /// <summary>
        /// Name
        /// </summary>
        public virtual string UserName { get; set; }

        /// <summary>
        /// normalized user name
        /// </summary>
        public virtual string NormalizedUserName { get; set; }

        /// <summary>
        ///     Email
        /// </summary>
        public virtual string Email { get; set; }

        /// <summary>
        /// normalized email
        /// </summary>
        public virtual string NormalizedEmail { get; set; }

        /// <summary>
        ///     True if the email is confirmed, default is false
        /// </summary>
        public virtual bool EmailConfirmed { get; set; }

        /// <summary>
        ///     The salted/hashed form of the user password
        /// </summary>
        public virtual string PasswordHash { get; set; }

        /// <summary>
        /// A random value that should change whenever a users credentials change (password changed, login removed)
        /// </summary>
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        /// A random value that should change whenever a user is persisted to the store
        /// </summary>
        public virtual string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        ///     PhoneNumber for the user
        /// </summary>
        public virtual string PhoneNumber { get; set; }

        /// <summary>
        ///     True if the phone number is confirmed, default is false
        /// </summary>
        public virtual bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        ///     Is two factor enabled for the user
        /// </summary>
        public virtual bool TwoFactorEnabled { get; set; }

        /// <summary>
        ///     DateTime in UTC when lockout ends, any time in the past is considered not locked out.
        /// </summary>
        public virtual DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>
        ///     Is lockout enabled for this user
        /// </summary>
        public virtual bool LockoutEnabled { get; set; }

        /// <summary>
        ///     Used to record failures for the purposes of lockout
        /// </summary>
        public virtual int AccessFailedCount { get; set; }

        /// <summary>
        /// Navigation property
        /// </summary>
        public virtual ICollection<TestUserRole> Roles { get; private set; } = new List<TestUserRole>();
        /// <summary>
        /// Navigation property
        /// </summary>
        public virtual ICollection<TestUserClaim> Claims { get; private set; } = new List<TestUserClaim>();
        /// <summary>
        /// Navigation property
        /// </summary>
        public virtual ICollection<TestUserLogin> Logins { get; private set; } = new List<TestUserLogin>();
        /// <summary>
        /// Navigation property
        /// </summary>
        public virtual ICollection<TestUserToken> Tokens { get; private set; } = new List<TestUserToken>();

    }
}
