using System;
using AspNetCore.Identity.ArangoDbCore.Infrastructure;
using AspNetCore.Identity.ArangoDbCore.Interfaces;
using Microsoft.Extensions.Configuration;

namespace AspNetCore.Identity.ArangoDbCore.Test.Infrastructure
{
    public static class Container
    {
        public static IConfiguration Configuration { get; set; }

        static Container()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(System.Environment.CurrentDirectory)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                //per user config that is not committed to repo, use this to override settings (e.g. connection string) based on your local environment.
                .AddJsonFile($"appsettings.local.json", optional: true);

            builder.AddEnvironmentVariables();

            Configuration = builder.Build();

            Settings = Configuration.Load<ArangoDbSettings>("ArangoDbSettings");

            ArangoDbIdentityConfiguration = new ArangoDbIdentityConfiguration()
            {
                ArangoDbSettings = Settings,
                IdentityOptionsAction = (options) =>
                {
                    options.Password.RequireDigit = false;
                    options.Password.RequireLowercase = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequireUppercase = false;
                    options.User.AllowedUserNameCharacters = null;
                }
            };

            ArangoRepository = new ArangoRepository(Settings);
        }

        public static ArangoDbSettings Settings { get; set; }
        public static ArangoDbIdentityConfiguration ArangoDbIdentityConfiguration { get; set; }

        public static IServiceProvider Instance { get; set; }

        public static IArangoDbRepository ArangoRepository { get; }
    }


    public static class ConfigurationExtensions
    {
        public static T Load<T>(this IConfiguration configuration, string key) where T : new()
        {
            var instance = new T();
            configuration.GetSection(key).Bind(instance);
            return instance;
        }

        public static T Load<T>(this IConfiguration configuration, string key, T instance) where T : new()
        {
            configuration.GetSection(key).Bind(instance);
            return instance;
        }
    }
}
