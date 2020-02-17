using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace ArangoDb.Net.Identity
{

/// <summary>
    /// A document representing an <see cref="IdentityUser{TKey}"/> document.
    /// </summary>
    /// <typeparam name="TKey">The type of the primary key.</typeparam>
    /// <remarks>We're only using the string value we get from the <c>_id</c> of the record in ArangoDB.</remarks>
    public class ArangoIdentityUser<TKey> : IdentityUser<TKey>, IClaimHolder
        where TKey : IEquatable<TKey>
    {
        public override TKey Id { get; set; }
        public List<ArangoClaim> Claims { get; set; }

        /// <summary>
        /// The ArangoDB identity. Do not alter.
        /// </summary>
        public string _id { get; set; }
        /// <summary>
        /// The ArangoDB key. Do not alter.
        /// </summary>
        public string _key { get; set; }
        /// <summary>
        /// The ArangoDB revision ID. Do not alter.
        /// </summary>
        public string _rev { get; set; }
        /// <summary>
        /// The role Ids of the roles that this user has.
        /// </summary>
        public List<TKey> Roles { get; set; }
        /// <summary>
        /// The list of <see cref="UserLoginInfo"/>s that this user has.
        /// </summary>
        public List<UserLoginInfo> Logins { get; set; }
    }

    /// <summary>
    /// See <see cref="ArangoIdentityUser{TKey}"/> where TKey is a <see cref="string"/>
    /// </summary>
    public class ArangoIdentityUser : ArangoIdentityUser<string>
    {
        public override string Id { get; set; }

        #region Login Management
        /// <summary>
        /// Adds a user login to the user.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> you want to add.</param>
        /// <returns>True if the addition was successful.</returns>
        public virtual bool AddLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo == null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }
            if (HasLogin(userLoginInfo))
            {
                return false;
            }

            Logins.Add(new UserLoginInfo(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey, userLoginInfo.ProviderDisplayName));
            return true;
        }
        /// <summary>
        /// Checks if the user has the given <see cref="UserLoginInfo"/>.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> we are looking for.</param>
        /// <returns>True if the user has the given <see cref="UserLoginInfo"/>.</returns>
        public virtual bool HasLogin(UserLoginInfo userLoginInfo)
        {
            return Logins.Any(e => e.LoginProvider == userLoginInfo.LoginProvider && e.ProviderKey == e.ProviderKey);
        }

        /// <summary>
        /// Checks if the user has the given <see cref="UserLoginInfo"/>.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> we are looking for.</param>
        /// <returns>True if the user has the given <see cref="UserLoginInfo"/>.</returns>
        public virtual bool HasLogin(UserLoginInfo userLoginInfo)
        {
            return Logins.Any(e => e.LoginProvider == userLoginInfo.LoginProvider && e.ProviderKey == e.ProviderKey);
        }

        /// <summary>
        /// Removes a <see cref="UserLoginInfo"/> from the user.
        /// </summary>
        /// <param name="userLoginInfo"></param>
        public virtual bool RemoveLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo == null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }
            var loginToremove = Logins.FirstOrDefault(e => e.LoginProvider == userLoginInfo.LoginProvider && e.ProviderKey == e.ProviderKey);
            if (loginToremove != null)
            {
                Logins.Remove(loginToremove);
                return true;
            }
            return false;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="loginProvider"></param>
        /// <param name="providerKey"></param>
        /// <returns></returns>
        public virtual IdentityUserLogin<TKey> GetUserLogin(string loginProvider, string providerKey)
        {

            var login = Logins.FirstOrDefault(e => e.LoginProvider == loginProvider && e.ProviderKey == providerKey);
            if (login != null)
            {
                return new IdentityUserLogin<TKey>
                {
                    UserId = Id,
                    LoginProvider = login.LoginProvider,
                    ProviderDisplayName = login.ProviderDisplayName,
                    ProviderKey = login.ProviderKey
                };
            }
            return default(IdentityUserLogin<TKey>);
        }

        #endregion




    }
}
