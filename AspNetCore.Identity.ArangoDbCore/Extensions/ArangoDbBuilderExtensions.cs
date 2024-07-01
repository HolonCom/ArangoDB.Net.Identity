using System;
using System.Reflection;
using AspNetCore.Identity.ArangoDbCore.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using AspNetCore.Identity.ArangoDbCore.Models;
using AspNetCore.Identity.ArangoDbCore.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AspNetCore.Identity.ArangoDbCore.Extensions
{
    /// <summary>
    /// Contains extension methods to <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> for adding ArangoDb stores.
    /// </summary>
    public static class ArangoDbBuilderExtensions
    {
        /// <summary>
        /// Adds an ArangoDb implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TContext">The ArangoDb database context to use.</typeparam>
        /// <param name="builder">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> instance this method extends.</param>
        /// <param name="arangoDbContext">A ArangoDbContext</param>
        /// <returns>The <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> instance this method extends.</returns>
        public static IdentityBuilder AddArangoDbStores<TContext>(
            this IdentityBuilder builder,
            IArangoDbContext arangoDbContext)
            where TContext : IArangoDbContext
        {
            if (arangoDbContext == null)
                throw new ArgumentNullException(nameof (arangoDbContext));
            builder.Services.TryAddSingleton<IArangoDbContext>(arangoDbContext);
            builder.Services.TryAddSingleton<IArangoDbRepository>((IArangoDbRepository) new ArangoRepository(arangoDbContext));
            return builder;
        }

        /// <summary>
        /// Adds an ArangoDb implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <typeparam name="TRole">The type representing a role.</typeparam>
        /// <typeparam name="TKey">The type of the primary key of the identity document.</typeparam>
        /// <param name="builder">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> instance this method extends.</param>
        /// <param name="uri"></param>
        /// <param name="databaseName"></param>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        public static IdentityBuilder AddArangoDbStores<TUser, TRole, TKey>(
            this IdentityBuilder builder,
            string uri,
            string databaseName,
            string userName,
            string password)
            where TUser : ArangoIdentityUser, new()
            where TRole : ArangoIdentityRole, new()
            where TKey : IEquatable<TKey>
        {
            var settings = new ArangoDbSettings()
                {Uri = uri, Database = databaseName, UserId = userName, Password = password};

            ServiceCollectionExtensions.ValidateArangoDbSettings(settings);

            builder.Services.TryAddSingleton(provider => settings);
            builder.AddArangoDbStores<TUser, TRole, TKey>(new ArangoDbContext(settings));
            return builder;
        }

        /// <summary>
        /// Adds an ArangoDb implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <typeparam name="TRole">The type representing a role.</typeparam>
        /// <typeparam name="TKey">The type of the primary key of the identity document.</typeparam>
        /// <param name="builder">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> instance this method extends.</param>
        /// <param name="arangoDbContext"></param>
        public static IdentityBuilder AddArangoDbStores<TUser, TRole, TKey>(
            this IdentityBuilder builder,
            IArangoDbContext arangoDbContext)
            where TUser : ArangoIdentityUser, new()
            where TRole : ArangoIdentityRole, new()
            where TKey : IEquatable<TKey>
        {
            if (arangoDbContext == null)
                throw new ArgumentNullException(nameof (arangoDbContext));
            builder.Services.TryAddSingleton(arangoDbContext);
            builder.Services.TryAddSingleton((IArangoDbRepository) new ArangoRepository(arangoDbContext));
            builder.Services.TryAddScoped(provider =>
                (IUserStore<TUser>) new ArangoUserStore<TUser, TRole, IArangoDbContext>(provider.GetService<IArangoDbContext>()));
            builder.Services.TryAddScoped(provider =>
                (IRoleStore<TRole>) new ArangoRoleStore<TRole, IArangoDbContext>(provider.GetService<IArangoDbContext>()));
            return builder;
        }

        private static TypeInfo FindGenericBaseType(Type currentType, Type genericBaseType)
        {
            var type = currentType;
            while (type != null)
            {
                var typeInfo = type.GetTypeInfo();
                var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
                if (genericType != null && genericType == genericBaseType)
                {
                    return typeInfo;
                }
                type = type.BaseType;
            }
            return null;
        }
    }
}
