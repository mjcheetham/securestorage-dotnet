using System;
using System.Runtime.InteropServices;

namespace Mjcheetham.SecureStorage
{
    internal static class NativeMethods
    {
        public static class Windows
        {
        }

        public static class MacOS
        {
            private const string CoreFoundationFrameworkLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
            private const string SecurityFrameworkLib = "/System/Library/Frameworks/Security.framework/Security";

            private const int OK = 0;
            private const int ErrorSecDuplicateItem = -25299;
            private const int ErrorSecItemNotFound = -25300;
            private const int ErrorSecInteractionNotAllowed = -25308;

            public static void ThrowOnError(int error, string defaultErrorMessage = null)
            {
                switch (error)
                {
                    case OK:
                        return;
                    case ErrorSecDuplicateItem:
                        throw new Exception("Item already exists");
                    case ErrorSecItemNotFound:
                        throw new Exception("Item does not exist");
                    case ErrorSecInteractionNotAllowed:
                        throw new Exception("Interaction not allowed");
                    default:
                        if (defaultErrorMessage == null)
                        {
                            throw new Exception($"Unknown error {error}");
                        }
                        else
                        {
                            throw new Exception($"{defaultErrorMessage}. Unknown error {error}");
                        }
                }
            }

            [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern void CFRelease(IntPtr cf);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainAddGenericPassword(
                IntPtr keychain,
                uint serviceNameLength,
                string serviceName,
                uint accountNameLength,
                string accountName,
                uint passwordLength,
                byte[] passwordData,
                out IntPtr itemRef);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainFindGenericPassword(
                IntPtr keychainOrArray,
                uint serviceNameLength,
                string serviceName,
                uint accountNameLength,
                string accountName,
                out uint passwordLength,
                out IntPtr passwordData,
                out IntPtr itemRef);


            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainItemFreeContent(
                IntPtr attrList,
                IntPtr data);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainItemModifyAttributesAndData(
                IntPtr itemRef,
                IntPtr attrList,
                uint length,
                byte[] data);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainItemDelete(
                IntPtr itemRef);
        }
    }
}
