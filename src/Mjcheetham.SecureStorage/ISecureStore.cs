using System.Collections.Generic;

namespace Mjcheetham.SecureStorage
{
    public interface ISecureStore
    {
        /// <summary>
        /// Get credential from the store with the specified key.
        /// </summary>
        /// <param name="key">Key for credential to retrieve.</param>
        /// <returns>Stored credential.</returns>
        /// <exception cref="KeyNotFoundException">Thrown if no credential exists in the store with the specified key.</exception>
        ICredential Get(string key);

        /// <summary>
        /// Add or update credential in the store with the specified key.
        /// </summary>
        /// <param name="key">Key for credential to add/update.</param>
        /// <param name="credential">Credential to store.</param>
        void AddOrUpdate(string key, ICredential credential);

        /// <summary>
        /// Delete credential from the store with the specified key.
        /// </summary>
        /// <param name="key">Key of credential to delete.</param>
        /// <returns>True if the credential was deleted, false otherwise.</returns>
        bool Remove(string key);
    }

    public interface ICredential
    {
        string UserName { get; }
        string Password { get; }
    }

    public class Credential : ICredential
    {
        public Credential(string userName, string password)
        {
            UserName = userName;
            Password = password;
        }

        public string UserName { get; }

        public string Password { get; }
    }
}
