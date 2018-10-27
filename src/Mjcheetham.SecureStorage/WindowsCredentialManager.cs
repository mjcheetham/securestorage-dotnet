using System;
using System.Runtime.InteropServices;
using System.Text;
using static Mjcheetham.SecureStorage.NativeMethods.Windows;

namespace Mjcheetham.SecureStorage
{
    public class WindowsCredentialManager : ISecureStore
    {
        #region Constructors

        public static WindowsCredentialManager OpenDefault()
        {
            return new WindowsCredentialManager();
        }

        private WindowsCredentialManager() { }

        #endregion

        #region ISecureStore

        public string Get(string key)
        {
            IntPtr credPtr = IntPtr.Zero;

            try
            {
                ThrowOnError(
                    CredRead(key, CredentialType.Generic, 0, out credPtr),
                    "Failed to read item from store."
                );

                Credential credential = Marshal.PtrToStructure<Credential>(credPtr);

                byte[] passwordBytes = new byte[credential.CredentialBlobSize];

                Marshal.Copy(credential.CredentialBlob, passwordBytes, 0, credential.CredentialBlobSize);

                return Encoding.Unicode.GetString(passwordBytes);
            }
            finally
            {
                if (credPtr != IntPtr.Zero)
                {
                    CredFree(credPtr);
                }
            }
        }

        public void AddOrUpdate(string key, string value)
        {
            byte[] data = Encoding.Unicode.GetBytes(value);

            var credential = new Credential
            {
                Type = CredentialType.Generic,
                TargetName = key,
                CredentialBlob = Marshal.AllocCoTaskMem(data.Length),
                CredentialBlobSize = data.Length,
                Persist = CredentialPersist.LocalMachine,
                AttributeCount = 0,
                UserName = Environment.UserName,
            };

            try
            {
                Marshal.Copy(data, 0, credential.CredentialBlob, data.Length);

                ThrowOnError(
                    CredWrite(ref credential, 0),
                    "Failed to write item to store."
                );
            }
            finally
            {
                if (credential.CredentialBlob != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(credential.CredentialBlob);
                }
            }
        }

        public bool Remove(string key)
        {
            if (!CredDelete(key, CredentialType.Generic, 0))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ERROR_NOT_FOUND)
                {
                    return false;
                }
                ThrowException(error, "Failed to delete item from store.");
            }

            return true;
        }

        #endregion
    }
}
