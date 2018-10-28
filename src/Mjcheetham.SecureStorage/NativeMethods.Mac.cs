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

            private const int OK = 0;
            private const int ErrorSecNoSuchKeychain = -25294;
            private const int ErrorSecInvalidKeychain = -25295;
            private const int ErrorSecAuthFailed = -25293;
            private const int ErrorSecDuplicateItem = -25299;
            private const int ErrorSecItemNotFound = -25300;
            private const int ErrorSecInteractionNotAllowed = -25308;
            private const int ErrorSecInteractionRequired = -25315;
            private const int ErrorSecNoSuchAttr = -25303;

            public static void ThrowOnError(int error, string defaultErrorMessage = "Unknown error.")
            {
                switch (error)
                {
                    case OK:
                        return;
                    case ErrorSecNoSuchKeychain:
                        throw new InvalidOperationException($"The keychain does not exist. ({ErrorSecNoSuchKeychain})");
                    case ErrorSecInvalidKeychain:
                        throw new InvalidOperationException($"The keychain is not valid. ({ErrorSecInvalidKeychain})");
                    case ErrorSecAuthFailed:
                        throw new InvalidOperationException($"Authorization/Authentication failed. ({ErrorSecAuthFailed})");
                    case ErrorSecDuplicateItem:
                        throw new ArgumentException($"The item already exists. ({ErrorSecDuplicateItem})");
                    case ErrorSecItemNotFound:
                        throw new KeyNotFoundException($"The item cannot be found. ({ErrorSecItemNotFound})");
                    case ErrorSecInteractionNotAllowed:
                        throw new InvalidOperationException($"Interaction with the Security Server is not allowed. ({ErrorSecInteractionNotAllowed})");
                    case ErrorSecInteractionRequired:
                        throw new InvalidOperationException($"User interaction is required. ({ErrorSecInteractionRequired})");
                    case ErrorSecNoSuchAttr:
                        throw new InvalidOperationException($"The attribute does not exist. ({ErrorSecNoSuchAttr})");
                    default:
                        throw new Exception($"{defaultErrorMessage} ({error})");
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SecKeychainAttributeInfo
            {
                public uint Count;
                public IntPtr Tag; // uint* (SecKeychainAttrType*)
                public IntPtr Format; // uint* (CssmDbAttributeFormat*)
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SecKeychainAttributeList
            {
                public uint Count;
                public IntPtr Attributes; // SecKeychainAttribute*
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SecKeychainAttribute
            {
                public SecKeychainAttrType Tag;
                public uint Length;
                public IntPtr Data;
            }

            public enum CssmDbAttributeFormat : uint
            {
                String = 0,
                SInt32 = 1,
                UInt32 = 2,
                BigNum = 3,
                Real = 4,
                TimeDate = 5,
                Blob = 6,
                MultiUInt32 = 7,
                Complex = 8
            };

            public enum SecKeychainAttrType : uint
            {
                AccountItem = 1633903476,
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
            public static extern int SecKeychainItemCopyAttributesAndData(
                IntPtr itemRef,
                ref SecKeychainAttributeInfo info,
                IntPtr itemClass, // SecItemClass*
                out IntPtr attrList, // SecKeychainAttributeList*
                out uint dataLength,
                IntPtr data);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainItemModifyAttributesAndData(
                IntPtr itemRef,
                IntPtr attrList, // SecKeychainAttributeList*
                uint length,
                byte[] data);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainItemDelete(
                IntPtr itemRef);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainItemFreeContent(
                IntPtr attrList, // SecKeychainAttributeList*
                IntPtr data);

            [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
            public static extern int SecKeychainItemFreeAttributesAndData(
                IntPtr attrList, // SecKeychainAttributeList*
                IntPtr data);

        }
    }
}
