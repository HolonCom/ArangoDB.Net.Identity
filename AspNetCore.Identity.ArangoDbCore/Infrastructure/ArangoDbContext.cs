using System;
using ArangoDBNetStandard;
using ArangoDBNetStandard.Transport.Http;
using AspNetCore.Identity.ArangoDbCore.Interfaces;

namespace AspNetCore.Identity.ArangoDbCore.Infrastructure
{
    public class ArangoDbContext: IArangoDbContext, IDisposable
    {
        private readonly ArangoDbSettings settings;
        private HttpApiTransport transport;
        public ArangoDbContext(ArangoDbSettings arangoDbSettings)
        {
            settings = arangoDbSettings;
            Init();
        }

        private void Init()
        {
            transport =
                HttpApiTransport.UsingBasicAuth(new Uri(settings.Uri), settings.Database, settings.UserId, settings.Password);
            Client = new ArangoDBClient(transport);
        }
        public ArangoDBClient Client { get; set; }

        public void Dispose()
        {
            transport.Dispose();
            Client?.Dispose();
        }
    }
}
