using System.Threading.Tasks;
using AspNetCore.Identity.ArangoDbCore.Interfaces;

namespace AspNetCore.Identity.ArangoDbCore.Infrastructure
{

    public class ArangoRepository: IArangoDbRepository
    {
        public ArangoRepository(string uri, string database, string user, string password)
        {
            Context = new ArangoDbContext(new ArangoDbSettings(){Database = database,Uri = uri,UserId = user,Password = password});
        }

        public ArangoRepository(ArangoDbSettings arangoDbSettings)
        {
            Context = new ArangoDbContext(arangoDbSettings);
        }

        public ArangoRepository(ArangoDbContext context)
        {
            Context = context;
        }

        public ArangoRepository(IArangoDbContext context)
        {
            Context = context;
        }

        public async Task DropDatabase(string databaseName)
        {
            await Context.Client.Database.DeleteDatabaseAsync(databaseName);
        }

        public async Task DropCollection(string collectionName)
        {
            await Context.Client.Collection.DeleteCollectionAsync(collectionName);
        }

        public IArangoDbContext Context { get; set; }
    }
}
