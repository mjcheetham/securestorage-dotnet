﻿using System.Collections.Generic;

namespace Mjcheetham.SecureStorage
{
    /// <summary>
    /// Represents a secure storage location for <see cref="ICredential"/>s.
    /// </summary>
    public interface ICredentialStore
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
}
