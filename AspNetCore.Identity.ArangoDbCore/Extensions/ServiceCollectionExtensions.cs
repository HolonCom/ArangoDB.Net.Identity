using System;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using AspNetCore.Identity.ArangoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.Identity.ArangoDbCore.Extensions
{
    /// <summary>
    /// Contains extension methods to <see cref="T:Microsoft.Extensions.DependencyInjection.IServiceCollection" /> for adding ArangoDb Identity.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Configures the ArangoDb Identity store adapters for the types of TUser only from <see cref="T:AspNetCore.Identity.ArangoDbCore.Models.ArangoIdentityUser`1" />.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <typeparam name="TKey">The type of the primary key of the identity document.</typeparam>
        /// <param name="services">The collection of service descriptors.</param>
        /// <param name="arangoDbIdentityConfiguration">A configuration object of the AspNetCore.Identity.ArangoDbCore package.</param>
        public static void ConfigureArangoDbIdentityUserOnly<TUser, TKey>(
            this IServiceCollection services,
            ArangoDbIdentityConfiguration arangoDbIdentityConfiguration)
            where TUser : ArangoIdentityUser, new()
            where TKey : IEquatable<TKey>
        {
            ValidateArangoDbSettings(arangoDbIdentityConfiguration.ArangoDbSettings);
            services.CommonArangoDbSetup<TUser, ArangoIdentityRole, TKey>(arangoDbIdentityConfiguration);
        }

        /// <summary>
        /// Configures the ArangoDb Identity store adapters for the types of TUser only inheriting from <see cref="T:AspNetCore.Identity.ArangoDbCore.Models.ArangoIdentityUser" />.
        /// </summary>
        /// <typeparam name="TUser">The type representing a user.</typeparam>
        /// <param name="services">The collection of service descriptors.</param>
        /// <param name="arangoDbIdentityConfiguration">A configuration object of the AspNetCore.Identity.ArangoDbCore package.</param>
        public static void ConfigureArangoDbIdentity<TUser>(
            this IServiceCollection services,
            ArangoDbIdentityConfiguration arangoDbIdentityConfiguration)
            where TUser : ArangoIdentityUser, new()
        {
            ValidateArangoDbSettings(arangoDbIdentityConfiguration.ArangoDbSettings);
            services.CommonArangoDbSetup<TUser, ArangoIdentityRole, Guid>(arangoDbIdentityConfiguration);
        }

   /// <summary>Validates the ArangoDbSettings</summary>
    /// <param name="ArangoDbSettings"></param>
    public static void ValidateArangoDbSettings(ArangoDbSettings ArangoDbSettings)
    {
      if (ArangoDbSettings == null)
        throw new ArgumentNullException(nameof (ArangoDbSettings));
      if (string.IsNullOrEmpty(ArangoDbSettings.Uri))
        throw new ArgumentNullException(nameof(ArangoDbSettings.Uri));
      if (string.IsNullOrEmpty(ArangoDbSettings.Database))
        throw new ArgumentNullException(nameof(ArangoDbSettings.Database));
      if (string.IsNullOrEmpty(ArangoDbSettings.UserId))
        throw  new ArgumentNullException(nameof(ArangoDbSettings.UserId));
      if (string.IsNullOrEmpty(ArangoDbSettings.Password))
        throw new ArgumentNullException(nameof(ArangoDbSettings.Password));
    }

    /// <summary>
    /// Configures the ArangoDb Identity store adapters for the types of TUser and TRole.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TKey">The type of the primary key of the identity document.</typeparam>
    /// <param name="services">The collection of service descriptors.</param>
    /// <param name="arangoDbIdentityConfiguration">A configuration object of the AspNetCore.Identity.ArangoDbCore package.</param>
    /// <param name="arangoDbContext">An object representing a ArangoDb connection.</param>
    public static void ConfigureArangoDbIdentity<TUser, TRole, TKey>(
      this IServiceCollection services,
      ArangoDbIdentityConfiguration arangoDbIdentityConfiguration,
      IArangoDbContext arangoDbContext = null)
      where TUser : ArangoIdentityUser, new()
      where TRole : ArangoIdentityRole, new()
      where TKey : IEquatable<TKey>
    {
      ValidateArangoDbSettings(arangoDbIdentityConfiguration.ArangoDbSettings);
      if (arangoDbContext == null)
        services.AddIdentity<TUser, TRole>().AddArangoDbStores<TUser, TRole, TKey>(
          arangoDbIdentityConfiguration.ArangoDbSettings.UserId,
          arangoDbIdentityConfiguration.ArangoDbSettings.Database,
          arangoDbIdentityConfiguration.ArangoDbSettings.UserId,
          arangoDbIdentityConfiguration.ArangoDbSettings.Password).AddDefaultTokenProviders();
      else
        services.AddIdentity<TUser, TRole>().AddArangoDbStores<IArangoDbContext>(arangoDbContext).AddDefaultTokenProviders();
      if (arangoDbIdentityConfiguration.IdentityOptionsAction == null)
        return;
      services.Configure<IdentityOptions>(arangoDbIdentityConfiguration.IdentityOptionsAction);
    }

    private static void CommonArangoDbSetup<TUser, TRole, TKey>(
      this IServiceCollection services,
      ArangoDbIdentityConfiguration arangoDbIdentityConfiguration)
      where TUser : ArangoIdentityUser, new()
      where TRole : ArangoIdentityRole, new()
      where TKey : IEquatable<TKey>
    {
      services.AddIdentity<TUser, TRole>().AddArangoDbStores<TUser, TRole, TKey>(
        arangoDbIdentityConfiguration.ArangoDbSettings.Uri,
        arangoDbIdentityConfiguration.ArangoDbSettings.Database,
        arangoDbIdentityConfiguration.ArangoDbSettings.UserId,
        arangoDbIdentityConfiguration.ArangoDbSettings.Password).AddDefaultTokenProviders();
      if (arangoDbIdentityConfiguration.IdentityOptionsAction == null)
        return;
      services.Configure<IdentityOptions>(arangoDbIdentityConfiguration.IdentityOptionsAction);
    }

    }
}
