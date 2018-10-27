using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Mjcheetham.SecureStorage
{
    internal static partial class NativeMethods
    {
        // https://developer.apple.com/documentation/security/keychain_services/keychain_items
        public static class MacOS
        {
            private const string CoreFoundationFrameworkLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
            private const string SecurityFrameworkLib = "/System/Library/Frameworks/Security.framework/Security";

            public const int OK = 0;
            public const int ErrorSecNoSuchKeychain = -25294;
            public const int ErrorSecInvalidKeychain = -25295;
            public const int ErrorSecAuthFailed = -25293;
            public const int ErrorSecDuplicateItem = -25299;
            public const int ErrorSecItemNotFound = -25300;
            public const int ErrorSecInteractionNotAllowed = -25308;
            public const int ErrorSecInteractionRequired = -25315;

            public static void ThrowOnError(int error, string defaultErrorMessage = "Unknown error.")
            {
                switch (error)
                {
                    case OK:
                        return;
                    case ErrorSecNoSuchKeychain:
                        throw new InvalidOperationException("The keychain does not exist.");
                    case ErrorSecInvalidKeychain:
                        throw new InvalidOperationException("The keychain is not valid.");
                    case ErrorSecAuthFailed:
                        throw new InvalidOperationException("Authorization/Authentication failed.");
                    case ErrorSecDuplicateItem:
                        throw new ArgumentException("The item already exists.");
                    case ErrorSecItemNotFound:
                        throw new KeyNotFoundException("The item cannot be found.");
                    case ErrorSecInteractionNotAllowed:
                        throw new InvalidOperationException("Interaction with the Security Server is not allowed.");
                    case ErrorSecInteractionRequired:
                        throw new InvalidOperationException("User interaction is required.");
                    default:
                        throw new Exception($"{defaultErrorMessage} ({error})");
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
