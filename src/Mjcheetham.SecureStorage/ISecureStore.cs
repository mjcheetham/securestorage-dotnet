using System.Collections.Generic;

namespace Mjcheetham.SecureStorage
{
    public interface ISecureStore
    {
        /// <summary>
        /// Get item from the store with the specified key.
        /// </summary>
        /// <param name="key">Key for item to retrieve.</param>
        /// <returns>Stored value.</returns>
        /// <exception cref="KeyNotFoundException">Thrown if no item exists in the store with the specified key.</exception>
        string Get(string key);

        /// <summary>
        /// Add or update value in the store with the specified key.
        /// </summary>
        /// <param name="key">Key for item to add/update.</param>
        /// <param name="value">Value to store.</param>
        void AddOrUpdate(string key, string value);

        /// <summary>
        /// Delete item from the store with the specified key.
        /// </summary>
        /// <param name="key">Key of item to delete.</param>
        /// <returns>True if the item was deleted, false otherwise.</returns>
        bool Remove(string key);
    }
}
