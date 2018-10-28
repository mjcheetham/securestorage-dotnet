using System;

namespace Mjcheetham.SecureStorage
{
    public static class CredentialStore
    {
        /// <summary>
        /// Open the platform default credential store for the current user.
        /// </summary>
        /// <returns>Credential store for the current platform and user.</returns>
        public static ICredentialStore OpenDefault()
        {
            if (PlatformUtils.IsMacOS)
            {
                return MacOSKeychain.OpenDefault();
            }

            if (PlatformUtils.IsWindows)
            {
                return WindowsCredentialManager.OpenDefault();
            }

            if (PlatformUtils.IsUnix)
            {
                throw new NotImplementedException();
            }

            throw new PlatformNotSupportedException();
        }
    }
}
