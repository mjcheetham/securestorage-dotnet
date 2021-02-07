using System;
using System.Collections.Generic;
using System.Text;
using Mjcheetham.SecureStorage.Interop;
using System.Native.Apple.CoreFoundation;
using System.Native.Apple.Security;
using static System.Native.Apple.CoreFoundation.CoreFoundation;
using static System.Native.Apple.Security.Security;

namespace Mjcheetham.SecureStorage.MacOS
{
    public interface IKeychain
    {
        string FindGenericPassword(string service, string account);
        string FindInternetPassword(string server, string account, string path, ushort port, SecProtocolType protocol);
        void AddGenericPassword(string service, string account, string password);
        void AddInternetPassword(string server, string account, string path, ushort port, SecProtocolType protocol, string password);
        IKeychainItem FindItem(IKeychainItem query, bool returnData);
        IEnumerable<IKeychainItem> FindItems(IKeychainItem query);
        bool DeleteItem(IKeychainItem query);
        void AddItem(IKeychainItem item);
    }

    public enum KeychainItemType
    {
        GenericPassword,
        InternetPassword
    }

    public interface IKeychainItem : IDisposable
    {
        KeychainItemType Type { get; set; }
        SecAuthenticationType AuthenticationType { get; set; }
        SecProtocolType Protocol { get; set; }
        byte[] Data { get; set; }
        string Account { get; set; }
        string Label { get; set; }
        string Service { get; set; }
        string Server { get; set; }
        string Path { get; set; }
        short Port { get; set; }
        bool UseDataProtectionKeychain { get; set; }
    }

    public class KeychainItem : IKeychainItem
    {
        private KeychainItem() { }

        public static IKeychainItem Create(KeychainItemType type)
        {
            return new KeychainItem {Type = type};
        }

        public KeychainItemType Type { get; set; }
        public SecAuthenticationType AuthenticationType { get; set; }
        public SecProtocolType Protocol { get; set; }
        public byte[] Data { get; set; }
        public string Account { get; set; }
        public string Label { get; set; }
        public string Service { get; set; }
        public string Server { get; set; }
        public string Path { get; set; }
        public short Port { get; set; }

        // TODO: move to IKeychainQuery interface
        public bool UseDataProtectionKeychain { get; set; }

        public void Dispose() { }
    }

    public class Keychain : IKeychain
    {
        private readonly IntPtr _keychainPtr;

        #region Constructors

        /// <summary>
        /// Open the default keychain (current user's login keychain).
        /// </summary>
        /// <returns>Default keychain.</returns>
        public Keychain() : this(IntPtr.Zero)
        {
        }

        private Keychain(IntPtr keychainPtr)
        {
            PlatformUtils.EnsureMacOS();

            _keychainPtr = keychainPtr;
        }

        #endregion

        public unsafe string FindGenericPassword(string service, string account)
        {
            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            uint serviceLength = (uint) (service?.Length ?? 0);
            uint accountLength = (uint) (account?.Length ?? 0);

            try
            {
                int findResult = SecKeychainFindGenericPassword(
                    _keychainPtr,
                    serviceLength, service,
                    accountLength, account,
                    out uint passwordLength, out passwordData,
                    out itemRef);

                switch (findResult)
                {
                    case errSecSuccess:
                        return passwordData.ToString(passwordLength, Encoding.UTF8);

                    case errSecItemNotFound:
                        return null;

                    default:
                        ThrowIfError(findResult);
                        return null;
                }
            }
            finally
            {
                if (passwordData != IntPtr.Zero)
                {
                    SecKeychainItemFreeContent(null, passwordData);
                }

                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        public unsafe string FindInternetPassword(string server, string account, string path, ushort port, SecProtocolType protocol)
        {
            IntPtr passwordData = IntPtr.Zero;
            IntPtr itemRef = IntPtr.Zero;

            uint serverLength  = (uint) (server?.Length ?? 0);
            uint accountLength = (uint) (account?.Length ?? 0);
            uint pathLength    = (uint) (path?.Length ?? 0);

            try
            {
                int findResult = SecKeychainFindInternetPassword(
                    _keychainPtr,
                    serverLength, server,
                    0, null,
                    accountLength, account,
                    pathLength, path,
                    port, protocol,
                    SecAuthenticationType.Default,
                    out uint passwordLength, out passwordData,
                    out itemRef);

                switch (findResult)
                {
                    case errSecSuccess:
                        return passwordData.ToString(passwordLength, Encoding.UTF8);

                    case errSecItemNotFound:
                        return null;

                    default:
                        ThrowIfError(findResult);
                        return null;
                }
            }
            finally
            {
                if (passwordData != IntPtr.Zero)
                {
                    SecKeychainItemFreeContent(null, passwordData);
                }

                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        public void AddGenericPassword(string service, string account, string password)
        {
            byte[] passwordData = password.ToByteArray(Encoding.UTF8);
            uint passwordLength = (uint) passwordData.Length;

            IntPtr itemRef = IntPtr.Zero;

            uint serviceLength = (uint) (service?.Length ?? 0);
            uint accountLength = (uint) (account?.Length ?? 0);

            try
            {
                int addResult = SecKeychainAddGenericPassword(
                    _keychainPtr,
                    serviceLength, service,
                    accountLength, account,
                    passwordLength, passwordData,
                    out itemRef);

                ThrowIfError(addResult);
            }
            finally
            {
                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        public void AddInternetPassword(string server, string account, string path, ushort port, SecProtocolType protocol, string password)
        {
            byte[] passwordData = password.ToByteArray(Encoding.UTF8);
            uint passwordLength = (uint) passwordData.Length;

            IntPtr itemRef = IntPtr.Zero;

            uint serverLength  = (uint) (server?.Length ?? 0);
            uint accountLength = (uint) (account?.Length ?? 0);
            uint pathLength    = (uint) (path?.Length ?? 0);

            try
            {
                int addResult = SecKeychainAddInternetPassword(
                    _keychainPtr,
                    serverLength, server,
                    0, null,
                    accountLength, account,
                    pathLength, path,
                    port, protocol,
                    SecAuthenticationType.Default,
                    passwordLength, passwordData,
                    out itemRef);

                ThrowIfError(addResult);
            }
            finally
            {
                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        public IKeychainItem FindItem(IKeychainItem query, bool returnData)
        {
            IntPtr queryDict = CreateQueryDictionary(query);

            CFDictionarySetValue(queryDict, kSecMatchLimit, kSecMatchLimitOne);
            CFDictionarySetValue(queryDict, kSecReturnAttributes, kCFBooleanTrue);
            CFDictionarySetValue(queryDict, kSecReturnData, returnData ? kCFBooleanTrue : kCFBooleanFalse);

            int copyResult = SecItemCopyMatching(queryDict, out IntPtr resultPtr);

            switch (copyResult)
            {
                case errSecSuccess:
                    return new KeychainCFDictionaryItem(resultPtr);

                case errSecItemNotFound:
                    return null;

                default:
                    ThrowIfError(copyResult);
                    return null;
            }
        }

        private static IntPtr CreateQueryDictionary(IKeychainItem query)
        {
            // Just clone the internal CF(Mutable)Dictionary
            if (query is KeychainCFDictionaryItem keychainItem)
            {
                return CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 32, keychainItem.Dictionary);
            }

            // Copy all properties in to the dictionary
            IntPtr dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 32, IntPtr.Zero, IntPtr.Zero);

            switch (query.Type)
            {
                case KeychainItemType.GenericPassword:
                    CFDictionaryAddValue(dict, kSecClass, kSecClassGenericPassword);
                    break;
                case KeychainItemType.InternetPassword:
                    CFDictionaryAddValue(dict, kSecClass, kSecClassInternetPassword);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            // TODO
            //CFDictionaryAddValue(dict, kSecAttrAuthenticationType, ?);
            //CFDictionaryAddValue(dict, kSecAttrProtocol, ?);

            CFDictionaryAddValue(dict, kSecAttrAccount, CFString.Create(query.Account));
            CFDictionaryAddValue(dict, kSecAttrLabel,   CFString.Create(query.Label));
            CFDictionaryAddValue(dict, kSecAttrService, CFString.Create(query.Service));
            CFDictionaryAddValue(dict, kSecAttrServer,  CFString.Create(query.Server));
            CFDictionaryAddValue(dict, kSecAttrPath,    CFString.Create(query.Path));
            CFDictionaryAddValue(dict, kSecAttrPort,    CFNumber.Create(query.Port));

            CFDictionaryAddValue(dict, kSecUseDataProtectionKeychain,
                query.UseDataProtectionKeychain ? kCFBooleanTrue : kCFBooleanFalse);

            return dict;
        }

        public IEnumerable<IKeychainItem> FindItems(IKeychainItem query)
        {
            IntPtr queryDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 32, IntPtr.Zero, IntPtr.Zero);

            CFDictionarySetValue(queryDict, kSecMatchLimit, kSecMatchLimitAll);
            CFDictionarySetValue(queryDict, kSecReturnAttributes, kCFBooleanTrue);
            CFDictionarySetValue(queryDict, kSecReturnData, kCFBooleanFalse);

            int copyResult = SecItemCopyMatching(queryDict, out IntPtr resultPtr);

            switch (copyResult)
            {
                case errSecSuccess:
                    int count = CFArrayGetCount(resultPtr);
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr itemDict = CFArrayGetValueAtIndex(resultPtr, i);
                        yield return new KeychainCFDictionaryItem(itemDict);
                    }
                    break;

                case errSecItemNotFound:
                    yield break;

                default:
                    ThrowIfError(copyResult);
                    yield break;
            }
        }

        public bool DeleteItem(IKeychainItem query)
        {
            IntPtr queryDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 32, IntPtr.Zero, IntPtr.Zero);

            CFDictionarySetValue(queryDict, kSecMatchLimit, kSecMatchLimitOne);

            int deleteResult = SecItemDelete(queryDict);

            switch (deleteResult)
            {
                case errSecSuccess:
                    return true;

                case errSecItemNotFound:
                    return false;

                default:
                    ThrowIfError(deleteResult);
                    return false;
            }
        }

        public void AddItem(IKeychainItem item)
        {
            IntPtr itemDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 32, IntPtr.Zero, IntPtr.Zero);

            // TODO: populate CFDictionary

            int addResult = SecItemAdd(itemDict, out IntPtr _);

            switch (addResult)
            {
                case errSecSuccess:
                    return;

                default:
                    ThrowIfError(addResult);
                    return;
            }
        }

        private static void ThrowIfError(int error, string defaultErrorMessage = "Unknown error.")
        {
            switch (error)
            {
                case errSecSuccess:
                    return;
                case errSecNoSuchKeychain:
                    throw new InteropException("The keychain does not exist.", error);
                case errSecInvalidKeychain:
                    throw new InteropException("The keychain is not valid.", error);
                case errSecAuthFailed:
                    throw new InteropException("Authorization/Authentication failed.", error);
                case errSecDuplicateItem:
                    throw new InteropException("The item already exists.", error);
                case errSecItemNotFound:
                    throw new InteropException("The item cannot be found.", error);
                case errSecInteractionNotAllowed:
                    throw new InteropException("Interaction with the Security Server is not allowed.", error);
                case errSecInteractionRequired:
                    throw new InteropException("User interaction is required.", error);
                case errSecNoSuchAttr:
                    throw new InteropException("The attribute does not exist.", error);
                default:
                    throw new InteropException(defaultErrorMessage, error);
            }
        }
    }

    internal class KeychainCFDictionaryItem : IKeychainItem
    {
        private readonly IntPtr _dict;

        public IntPtr Dictionary => _dict;

        public KeychainCFDictionaryItem(IntPtr dict)
        {
            _dict = dict;
        }

        public KeychainItemType Type
        {
            get
            {
                IntPtr value = CFDictionaryGetValue(_dict, kSecClass);
                if (value == kSecClassGenericPassword)
                {
                    return KeychainItemType.GenericPassword;
                }

                if (value == kSecClassInternetPassword)
                {
                    return KeychainItemType.InternetPassword;
                }

                throw new InvalidOperationException();
            }
            set
            {
                switch (value)
                {
                    case KeychainItemType.GenericPassword:
                        CFDictionarySetValue(_dict, kSecClass, kSecClassGenericPassword);
                        break;

                    case KeychainItemType.InternetPassword:
                        CFDictionarySetValue(_dict, kSecClass, kSecClassInternetPassword);
                        break;

                    default:
                        throw new ArgumentOutOfRangeException(nameof(value));
                }
            }
        }

        public SecAuthenticationType AuthenticationType
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrAuthenticationType);
                if (valuePtr != IntPtr.Zero)
                {
                    byte[] code = CFString.ToBytes(valuePtr, CFStringEncoding.kCFStringEncodingUTF8);
                    if (code != null)
                    {
                        return (SecAuthenticationType) FourCharCodeUtils.ToUInt32(code);
                    }
                }

                return SecAuthenticationType.Any;
            }
            set
            {
                if (value == SecAuthenticationType.Any)
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrAuthenticationType);
                }
                else
                {
                    byte[] codeBytes = FourCharCodeUtils.ToBytes((uint) value);
                    CFDictionarySetValue(_dict, kSecAttrAuthenticationType, CFString.Create(codeBytes));
                }
            }
        }

        public SecProtocolType Protocol
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrProtocol);
                if (valuePtr != IntPtr.Zero)
                {
                    byte[] code = CFString.ToBytes(valuePtr, CFStringEncoding.kCFStringEncodingUTF8);
                    if (code != null)
                    {
                        return (SecProtocolType) FourCharCodeUtils.ToUInt32(code);
                    }
                }

                return SecProtocolType.Any;
            }
            set
            {
                if (value == SecProtocolType.Any)
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrProtocol);
                }
                else
                {
                    byte[] codeBytes = FourCharCodeUtils.ToBytes((uint) value);
                    CFDictionarySetValue(_dict, kSecAttrProtocol, CFString.Create(codeBytes));
                }
            }
        }

        public byte[] Data
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecValueData);
                return valuePtr != IntPtr.Zero ? CFData.ToArray(valuePtr) : null;
            }
            set
            {
                if (value is null)
                {
                    CFDictionaryRemoveValue(_dict, kSecValueData);
                }
                else
                {
                    CFDictionarySetValue(_dict, kSecValueData, CFData.Create(value));
                }
            }
        }

        public string Account
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrAccount);
                return valuePtr != IntPtr.Zero ? CFString.ToString(valuePtr) : null;
            }
            set
            {
                if (value is null)
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrAccount);
                }
                else
                {
                    CFDictionarySetValue(_dict, kSecAttrAccount, CFString.Create(value));
                }
            }
        }

        public string Label
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrLabel);
                return valuePtr != IntPtr.Zero ? CFString.ToString(valuePtr) : null;
            }
            set
            {
                if (value is null)
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrLabel);
                }
                else
                {
                    CFDictionarySetValue(_dict, kSecAttrLabel, CFString.Create(value));
                }
            }
        }

        public string Service
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrService);
                return valuePtr != IntPtr.Zero ? CFString.ToString(valuePtr) : null;
            }
            set
            {
                if (value is null)
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrService);
                }
                else
                {
                    CFDictionarySetValue(_dict, kSecAttrService, CFString.Create(value));
                }
            }
        }

        public string Server
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrServer);
                return valuePtr != IntPtr.Zero ? CFString.ToString(valuePtr) : null;
            }
            set
            {
                if (value is null)
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrServer);
                }
                else
                {
                    CFDictionarySetValue(_dict, kSecAttrServer, CFString.Create(value));
                }
            }
        }

        public string Path
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrPath);
                return valuePtr != IntPtr.Zero ? CFString.ToString(valuePtr) : null;
            }
            set
            {
                if (value is null)
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrPath);
                }
                else
                {
                    CFDictionarySetValue(_dict, kSecAttrPath, CFString.Create(value));
                }
            }
        }

        public short Port
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecAttrPort);
                return valuePtr != IntPtr.Zero ? CFNumber.ToInt16(valuePtr) : (short) 0;
            }
            set
            {
                if (value > 0)
                {
                    CFDictionarySetValue(_dict, kSecAttrPort, CFNumber.Create(value));
                }
                else
                {
                    CFDictionaryRemoveValue(_dict, kSecAttrPort);
                }
            }
        }

        public bool UseDataProtectionKeychain
        {
            get
            {
                IntPtr valuePtr = CFDictionaryGetValue(_dict, kSecUseDataProtectionKeychain);
                return valuePtr == kCFBooleanTrue;
            }
            set => CFDictionarySetValue(_dict, kSecUseDataProtectionKeychain,
                value ? kCFBooleanTrue : kCFBooleanFalse);
        }

        public void Dispose() => CFRelease(_dict);
    }
}
