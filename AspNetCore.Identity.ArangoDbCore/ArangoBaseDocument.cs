namespace AspNetCore.Identity.ArangoDbCore
{
    public class ArangoBaseDocument
    {
        public string _id { get; set; }

        public string _rev { get; set; }

        public string _key { get; set; }
    }
}
