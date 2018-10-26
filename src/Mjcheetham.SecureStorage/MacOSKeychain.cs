using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
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

        private uint UserNameLength => (uint)UserName.Length;

        private string UserName => Environment.UserName;

        #region ISecureStore

        public byte[] GetData(string key)
        {
            uint keyLength = (uint) key.Length;

            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            try
            {
                ThrowOnError(
                    SecKeychainFindGenericPassword(
                        IntPtr.Zero, keyLength, key, UserNameLength, UserName,
                        out uint passwordLength, out passwordData, out itemRef)
                );

                byte[] result = new byte[passwordLength];
                Marshal.Copy(passwordData, result, 0, result.Length);

                return result;
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

        public void SetData(string key, byte[] data)
        {
            uint keyLength = (uint) key.Length;
            uint dataLength = (uint) data.Length;

            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            try
            {
                // Check if an entry already exists in the keychain
                SecKeychainFindGenericPassword(
                    IntPtr.Zero, keyLength, key, UserNameLength, UserName,
                    out uint passwordLength, out passwordData, out itemRef);

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

        public bool DeleteData(string key)
        {
            uint keyLength = (uint) key.Length;

            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            try
            {
                SecKeychainFindGenericPassword(
                    IntPtr.Zero, keyLength, key, UserNameLength, UserName,
                    out uint passwordLength, out passwordData, out itemRef);

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

        public IEnumerable<string> ListKeys()
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}
