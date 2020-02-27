namespace AspNetCore.Identity.ArangoDbCore.Interfaces
{
    public class ArangoDbSettings
    {
        public string Uri { get; set; }
        public string Database { get; set; }
        public string UserId { get; set; }
        public string Password { get; set; }
    }
}
