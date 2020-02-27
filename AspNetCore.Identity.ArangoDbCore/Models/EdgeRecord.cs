namespace AspNetCore.Identity.ArangoDbCore.Models
{
    /// <summary>
    /// A generic edge record for reading/writing edge data.
    /// </summary>
    public class EdgeRecord
    {
        public string _id { get; set; }
        public string _rev { get; set; }
        public string _key { get; set; }
        public string _from { get; set; }
        public string _to { get; set; }
    }
}
