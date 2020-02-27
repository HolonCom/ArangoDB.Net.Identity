using ArangoDBNetStandard;

namespace AspNetCore.Identity.ArangoDbCore.Interfaces
{
    public interface IArangoDbContext
    {
        public ArangoDBClient Client { get; set; }
    }
}
