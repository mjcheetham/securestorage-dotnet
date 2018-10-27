using System;
using System.Runtime.InteropServices;
using System.Text;
using static Mjcheetham.SecureStorage.NativeMethods.MacOS;

namespace Mjcheetham.SecureStorage
{
    public class MacOSKeychain : ISecureStore
    {
        #region Constructors

        public static MacOSKeychain OpenDefault()
        {
            return new MacOSKeychain();
        }

        private MacOSKeychain() { }

        #endregion

        #region Private Properties

        private uint UserNameLength => (uint)UserName.Length;

        private string UserName => Environment.UserName;

        #endregion

        #region ISecureStore

        public string Get(string key)
        {
            var keyLength = (uint) key.Length;

            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            try
            {
                ThrowOnError(
                    SecKeychainFindGenericPassword(
                        IntPtr.Zero, keyLength, key, UserNameLength, UserName,
                        out uint passwordLength, out passwordData, out itemRef)
                );

                var data = new byte[passwordLength];
                Marshal.Copy(passwordData, data, 0, data.Length);

                return Encoding.UTF8.GetString(data);
            }
            finally
            {
                if (passwordData != IntPtr.Zero)
                {
                    SecKeychainItemFreeContent(IntPtr.Zero, passwordData);
                }

                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        public void AddOrUpdate(string key, string value)
        {
            byte[] data = Encoding.UTF8.GetBytes(value);

            var keyLength = (uint) key.Length;
            var dataLength = (uint) data.Length;

            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            try
            {
                // Check if an entry already exists in the keychain
                SecKeychainFindGenericPassword(
                    IntPtr.Zero, keyLength, key, UserNameLength, UserName,
                    out uint _, out passwordData, out itemRef);

                if (itemRef != IntPtr.Zero) // Update existing entry
                {
                    ThrowOnError(
                        SecKeychainItemModifyAttributesAndData(itemRef, IntPtr.Zero, (uint) data.Length, data),
                        "Could not update existing item"
                    );
                }
                else // Create new entry
                {
                    ThrowOnError(
                        SecKeychainAddGenericPassword(IntPtr.Zero, keyLength, key, UserNameLength,
                            UserName, dataLength, data, out itemRef),
                        "Could not create new item"
                    );
                }

            }
            finally
            {
                if (passwordData != IntPtr.Zero)
                {
                    SecKeychainItemFreeContent(IntPtr.Zero, passwordData);
                }

                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        public bool Remove(string key)
        {
            uint keyLength = (uint) key.Length;

            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            try
            {
                SecKeychainFindGenericPassword(
                    IntPtr.Zero, keyLength, key, UserNameLength, UserName,
                    out _, out passwordData, out itemRef);

                if (itemRef != IntPtr.Zero)
                {
                    ThrowOnError(
                        SecKeychainItemDelete(itemRef)
                    );

                    return true;
                }

                return false;
            }
            finally
            {
                if (passwordData != IntPtr.Zero)
                {
                    SecKeychainItemFreeContent(IntPtr.Zero, passwordData);
                }

                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        #endregion
    }
}
