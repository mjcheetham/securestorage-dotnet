using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mjcheetham.SecureStorage.Interop;
using Mjcheetham.SecureStorage.MacOS.Interop;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;
using static Mjcheetham.SecureStorage.MacOS.Interop.SecurityFramework;

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

        public string FindGenericPassword(string service, string account)
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
                    case OK:
                        return passwordData.ToString(passwordLength, Encoding.UTF8);

                    case ErrorSecItemNotFound:
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
                    SecKeychainItemFreeContent(IntPtr.Zero, passwordData);
                }

                if (itemRef != IntPtr.Zero)
                {
                    CFRelease(itemRef);
                }
            }
        }

        public string FindInternetPassword(string server, string account, string path, ushort port, SecProtocolType protocol)
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
                    case OK:
                        return passwordData.ToString(passwordLength, Encoding.UTF8);

                    case ErrorSecItemNotFound:
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
                    SecKeychainItemFreeContent(IntPtr.Zero, passwordData);
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
            if (!(query is KeychainItem kcQuery))
            {
                throw new ArgumentException($"Must be of type {nameof(KeychainItem)}", nameof(query));
            }

            kcQuery.Dictionary.Add(kSecMatchLimit, kSecMatchLimitOne);
            kcQuery.Dictionary.Add(kSecReturnAttributes, kCFBooleanTrue);
            kcQuery.Dictionary.Add(kSecReturnData, returnData ? kCFBooleanTrue : kCFBooleanFalse);

            int copyResult = SecItemCopyMatching(kcQuery.Dictionary.DangerousGetHandle(), out IntPtr resultPtr);

            switch (copyResult)
            {
                case OK:
                    var dict = new CFDictionary(resultPtr, false);
                    return new KeychainItem(dict);

                case ErrorSecItemNotFound:
                    return null;

                default:
                    ThrowIfError(copyResult);
                    return null;
            }
        }

        public IEnumerable<IKeychainItem> FindItems(IKeychainItem query)
        {
            if (!(query is KeychainItem kcQuery))
            {
                throw new ArgumentException($"Must be of type {nameof(KeychainItem)}", nameof(query));
            }

            kcQuery.Dictionary.Add(kSecMatchLimit, kSecMatchLimitAll);
            kcQuery.Dictionary.Add(kSecReturnAttributes, kCFBooleanTrue);
            kcQuery.Dictionary.Add(kSecReturnData, kCFBooleanFalse);

            int copyResult = SecItemCopyMatching(kcQuery.Dictionary.DangerousGetHandle(), out IntPtr resultPtr);

            switch (copyResult)
            {
                case OK:
                    CFType[] array = CFArray.ToArray(resultPtr);
                    foreach (CFDictionary dict in array.OfType<CFDictionary>())
                    {
                        yield return new KeychainItem(dict);
                    }
                    break;

                case ErrorSecItemNotFound:
                    yield break;

                default:
                    ThrowIfError(copyResult);
                    yield break;
            }
        }

        public bool DeleteItem(IKeychainItem query)
        {
            if (!(query is KeychainItem kcQuery))
            {
                throw new ArgumentException($"Must be of type {nameof(KeychainItem)}", nameof(query));
            }

            kcQuery.Dictionary.SetValue(kSecMatchLimit, kSecMatchLimitOne);

            int deleteResult = SecItemDelete(kcQuery.Dictionary.DangerousGetHandle());

            switch (deleteResult)
            {
                case OK:
                    return true;

                case ErrorSecItemNotFound:
                    return false;

                default:
                    ThrowIfError(deleteResult);
                    return false;
            }
        }

        public void AddItem(IKeychainItem item)
        {
            if (!(item is KeychainItem kcItem))
            {
                throw new ArgumentException($"Must be of type {nameof(KeychainItem)}", nameof(item));
            }

            int addResult = SecItemAdd(kcItem.Dictionary.DangerousGetHandle(), out IntPtr _);

            switch (addResult)
            {
                case OK:
                    return;

                default:
                    ThrowIfError(addResult);
                    return;
            }
        }
    }

    public class KeychainItem : IKeychainItem
    {
        private readonly CFDictionary _dict;

        public KeychainItem(KeychainItemType type)
            : this(new CFDictionary(32))
        {
            Type = type;
        }

        internal KeychainItem(CFDictionary dict)
        {
            _dict = dict;
        }

        internal CFDictionary Dictionary => _dict;

        public KeychainItemType Type
        {
            get
            {
                IntPtr value = _dict[kSecClass];
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
                        _dict[kSecClass] = kSecClassGenericPassword;
                        break;

                    case KeychainItemType.InternetPassword:
                        _dict[kSecClass] = kSecClassInternetPassword;
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
                if (_dict.TryGetValue(kSecAttrAuthenticationType, out IntPtr valuePtr))
                {
                    string code = CFString.ToString(valuePtr);
                    return (SecAuthenticationType) FourCharCodeUtils.ToUInt32(code);
                }

                return SecAuthenticationType.Any;
            }
            set
            {
                if (value == SecAuthenticationType.Any)
                {
                    _dict.Remove(kSecAttrAuthenticationType);
                }
                else
                {
                    string code = FourCharCodeUtils.ToString((uint) value);
                    _dict[kSecAttrAuthenticationType] = CFString.CreateHandle(code);
                }
            }
        }

        public SecProtocolType Protocol
        {
            get
            {
                if (_dict.TryGetValue(kSecAttrProtocol, out IntPtr valuePtr))
                {
                    string code = CFString.ToString(valuePtr);
                    return (SecProtocolType) FourCharCodeUtils.ToUInt32(code);
                }

                return SecProtocolType.Any;
            }
            set
            {
                if (value == SecProtocolType.Any)
                {
                    _dict.Remove(kSecAttrProtocol);
                }
                else
                {
                    string code = FourCharCodeUtils.ToString((uint) value);
                    _dict[kSecAttrProtocol] = CFString.CreateHandle(code);
                }
            }
        }

        public byte[] Data
        {
            get => _dict.TryGetValue(kSecValueData, out IntPtr valuePtr) ? CFData.ToArray(valuePtr) : null;
            set
            {
                if (value is null)
                {
                    _dict.Remove(kSecValueData);
                }
                else
                {
                    _dict.SetValue(kSecValueData, CFData.CreateHandle(value));
                }
            }
        }

        public string Account
        {
            get => _dict.GetString(kSecAttrAccount);
            set => _dict.SetString(kSecAttrAccount, value);
        }

        public string Label
        {
            get => _dict.GetString(kSecAttrLabel);
            set => _dict.SetString(kSecAttrLabel, value);
        }

        public string Service
        {
            get => _dict.GetString(kSecAttrService);
            set => _dict.SetString(kSecAttrService, value);
        }

        public string Server
        {
            get => _dict.GetString(kSecAttrServer);
            set => _dict.SetString(kSecAttrServer, value);
        }

        public string Path
        {
            get => _dict.GetString(kSecAttrPath);
            set => _dict.SetString(kSecAttrPath, value);
        }

        public short Port
        {
            get => _dict.TryGetValue(kSecAttrPort, out IntPtr valuePtr) ? CFNumber.ToInt16(valuePtr) : (short) 0;
            set
            {
                if (value > 0)
                {
                    _dict.SetValue(kSecAttrPort, CFNumber.CreateHandle(value));
                }
                else
                {
                    _dict.Remove(kSecAttrPort);
                }
            }
        }

        public void Dispose() => _dict.Dispose();
    }
}
