using System;
using System.Text;
using Mjcheetham.SecureStorage.Interop;
using Mjcheetham.SecureStorage.MacOS.Interop;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;
using static Mjcheetham.SecureStorage.MacOS.Interop.SecurityFramework;

namespace Mjcheetham.SecureStorage.MacOS
{
    public class MacOSKeychain
    {
        private readonly IntPtr _keychainPtr;

        #region Constructors

        /// <summary>
        /// Open the default keychain (current user's login keychain).
        /// </summary>
        /// <returns>Default keychain.</returns>
        public MacOSKeychain() : this(IntPtr.Zero)
        {
        }

        private MacOSKeychain(IntPtr keychainPtr)
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

        public KeychainItem FindItem(KeychainQuery query)
        {
            query.Dictionary.Add(kSecMatchLimit, kSecMatchLimitOne);

            int copyResult = SecItemCopyMatching(query.Dictionary.DangerousGetHandle(), out IntPtr resultPtr);

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

        public bool DeleteItem(KeychainQuery query)
        {
            query.Dictionary.Add(kSecMatchLimit, kSecMatchLimitOne);

            int deleteResult = SecItemDelete(query.Dictionary.DangerousGetHandle());

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
    }

    public class KeychainItem : IDisposable
    {
        private readonly CFDictionary _dict;

        internal KeychainItem(CFDictionary dict)
        {
            _dict = dict;
        }

        internal CFDictionary Dictionary => _dict;

        public byte[] Data => _dict.TryGetValue(kSecValueData, out IntPtr value) ? CFData.ToArray(value) : null;

        public string Account => _dict.GetString(kSecAttrAccount);

        public string Label => _dict.GetString(kSecAttrLabel);

        public string Service => _dict.GetString(kSecAttrService);

        public SecAuthenticationType AuthenticationType
        {
            get
            {
                if (_dict.TryGetValue(kSecAttrAuthenticationType, out IntPtr valuePtr))
                {
                    return (SecAuthenticationType) CFNumber.ToInt32(valuePtr);
                }

                return SecAuthenticationType.Any;
            }
        }

        public SecProtocolType Protocol
        {
            get
            {
                if (_dict.TryGetValue(kSecAttrProtocol, out IntPtr valuePtr))
                {
                    return (SecProtocolType) CFNumber.ToInt32(valuePtr);
                }

                return SecProtocolType.Any;
            }
        }

        public string Server => _dict.GetString(kSecAttrServer);

        public short Port => _dict.TryGetValue(kSecAttrPort, out IntPtr valuePtr)
            ? CFNumber.ToInt16(valuePtr)
            : (short) 0;

        public string Path => _dict.GetString(kSecAttrPath);

        public void Dispose() => _dict.Dispose();
    }

    public class KeychainQuery : IDisposable
    {
        private readonly CFDictionary _dict;

        public KeychainQuery(KeychainItemType type)
        {
            _dict = new CFDictionary(32);

            // Always return attributes
            _dict.SetValue(kSecReturnAttributes, kCFBooleanTrue);

            Type = type;
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

        public bool ReturnData
        {
            get => _dict[kSecReturnData] == kCFBooleanTrue;
            set => _dict[kSecReturnData] = value ? kCFBooleanTrue : kCFBooleanFalse;
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

        public SecAuthenticationType AuthenticationType
        {
            get
            {
                if (_dict.TryGetValue(kSecAttrAuthenticationType, out IntPtr valuePtr))
                {
                    return (SecAuthenticationType) CFNumber.ToInt32(valuePtr);
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
                    _dict[kSecAttrAuthenticationType] = CFNumber.CreateHandle((uint) value);
                }
            }
        }

        public SecProtocolType Protocol
        {
            get
            {
                if (_dict.TryGetValue(kSecAttrProtocol, out IntPtr valuePtr))
                {
                    return (SecProtocolType) CFNumber.ToInt32(valuePtr);
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
                    _dict[kSecAttrProtocol] = CFNumber.CreateHandle((uint) value);
                }
            }
        }

        public string Server
        {
            get => _dict.GetString(kSecAttrServer);
            set => _dict.SetString(kSecAttrServer, value);
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

        public string Path
        {
            get => _dict.GetString(kSecAttrPath);
            set => _dict.SetString(kSecAttrPath, value);
        }

        public void Dispose() => _dict.Dispose();
    }

    public enum KeychainItemType
    {
        GenericPassword,
        InternetPassword
    }
}
