using System.ComponentModel;

namespace ArangoDb.Net.Identity.Extensions
{
    public static class StringExtensions
    {
        /// <summary>
        /// Converts the provided <paramref name="id"/> to a strongly typed key object.
        /// </summary>
        /// <typeparam name="TKey"></typeparam>
        /// <param name="id"></param>
        /// <returns></returns>
        public static TKey ToTKey<TKey>(this string id)
        {
            if (id == null)
            {
                return default;
            }
            var typeOfKey = typeof(TKey);
            return (TKey)TypeDescriptor.GetConverter(typeOfKey).ConvertFromInvariantString(id);
        }
    }
}
