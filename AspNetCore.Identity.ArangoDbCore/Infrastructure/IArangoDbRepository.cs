using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Interfaces;

namespace AspNetCore.Identity.ArangoDbCore.Infrastructure
{
    public interface IArangoDbRepository
    {
        /// <summary>
        /// Drops a database.
        /// </summary>
        Task DropDatabase(string databaseName);
        /// <summary>
        /// Drops a colleciton.
        /// </summary>
        /// <param name="collectionName">The collection name.</param>
        Task DropCollection(string collectionName);

        public IArangoDbContext Context { get; set; }
    }
}
