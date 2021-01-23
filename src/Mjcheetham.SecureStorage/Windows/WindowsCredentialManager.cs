using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Mjcheetham.SecureStorage.Interop;
using Mjcheetham.SecureStorage.Windows.Interop;

namespace Mjcheetham.SecureStorage.Windows
{
    public class WindowsCredentialManager
    {
        #region Constructors

        /// <summary>
        /// Open the Windows Credential Manager vault for the current user.
        /// </summary>
        /// <returns>Current user's Credential Manager vault.</returns>
        public  WindowsCredentialManager()
        {
            PlatformUtils.EnsureWindows();
        }

        #endregion

        public IEnumerable<WindowsCredential> Enumerate(string filter)
        {
            IntPtr listPtr = IntPtr.Zero;
            var flags = CredentialEnumerateFlags.EnumerateAll;

            if (string.IsNullOrEmpty(filter) || filter == "*")
            {
                filter = null;

                // Valid for Vista and later only
                if (Environment.OSVersion.Version.Major > 5)
                {
                    flags = CredentialEnumerateFlags.EnumerateAll;
                }
            }

            try
            {
                int result = Win32Error.GetLastError(
                    Advapi32.CredEnumerate(filter, flags, out int count, out listPtr)
                );

                switch (result)
                {
                    case Win32Error.Success:
                        break;

                    case Win32Error.NotFound:
                        yield break;

                    default:
                        Win32Error.ThrowIfError(result, "Failed to enumerate items in store.");
                        yield break;
                }

                for (int i = 0; i < count; i++)
                {
                    IntPtr ptr = Marshal.ReadIntPtr(listPtr, i * Marshal.SizeOf(typeof(IntPtr)));
                    yield return ReadCredential(ptr);
                }
            }
            finally
            {
                if (listPtr != IntPtr.Zero)
                {
                    Advapi32.CredFree(listPtr);
                }
            }
        }

        public WindowsCredential Read(string targetName)
        {
            IntPtr credPtr = IntPtr.Zero;

            try
            {
                int result = Win32Error.GetLastError(
                    Advapi32.CredRead(targetName, CredentialType.Generic, 0, out credPtr)
                );

                switch (result)
                {
                    case Win32Error.Success:
                        return ReadCredential(credPtr);

                    case Win32Error.NotFound:
                        return null;

                    default:
                        Win32Error.ThrowIfError(result, "Failed to read item from store.");
                        return null;
                }
            }
            finally
            {
                if (credPtr != IntPtr.Zero)
                {
                    Advapi32.CredFree(credPtr);
                }
            }
        }

        public void Write(WindowsCredential credential)
        {
            byte[] passwordBytes = Encoding.Unicode.GetBytes(credential.Password);

            var w32Credential = new Win32Credential
            {
                Type = CredentialType.Generic,
                TargetName = credential.TargetName,
                CredentialBlob = Marshal.AllocHGlobal(passwordBytes.Length),
                CredentialBlobSize = passwordBytes.Length,
                Persist = CredentialPersist.LocalMachine,
                AttributeCount = 0,
                UserName = credential.UserName,
                Comment = credential.Comment
            };

            try
            {
                Marshal.Copy(passwordBytes, 0, w32Credential.CredentialBlob, passwordBytes.Length);

                int result = Win32Error.GetLastError(
                    Advapi32.CredWrite(ref w32Credential, 0)
                );

                Win32Error.ThrowIfError(result, "Failed to write item to store.");
            }
            finally
            {
                if (w32Credential.CredentialBlob != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(w32Credential.CredentialBlob);
                }
            }
        }

        public bool Delete(string targetName)
        {
            int result = Win32Error.GetLastError(
                Advapi32.CredDelete(targetName, CredentialType.Generic, 0)
            );

            switch (result)
            {
                case Win32Error.Success:
                    return true;

                case Win32Error.NotFound:
                    return false;

                default:
                    Win32Error.ThrowIfError(result);
                    return false;
            }
        }

        private static WindowsCredential ReadCredential(IntPtr ptr)
        {
            Win32Credential credential = Marshal.PtrToStructure<Win32Credential>(ptr);

            byte[] passwordBytes = IntPtrExtensions.ToByteArray(credential.CredentialBlob, credential.CredentialBlobSize);
            var password = Encoding.Unicode.GetString(passwordBytes);

            return new WindowsCredential(credential.TargetName, credential.UserName, password)
            {
                Comment = credential.Comment,
                Persist = credential.Persist,
                LastWritten = credential.LastWritten.ToDateTimeUtc()
            };
        }
    }

    public class WindowsCredential
    {
        public WindowsCredential(string targetName, string userName, string password)
        {
            TargetName = targetName;
            UserName = userName;
            Password = password;
        }

        public string TargetName { get; }

        public string UserName { get; }

        public string Password { get; }

        public string Comment { get; set; }

        public CredentialPersist Persist { get; set; }

        public DateTime LastWritten { get; set; }
    }
}
