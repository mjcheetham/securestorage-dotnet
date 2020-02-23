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
        public static MacOSKeychain Open()
        {
            return new MacOSKeychain(IntPtr.Zero);
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

        public KeychainRecord FindItem(KeychainQuery query)
        {
            query.Add(kSecMatchLimit, kSecMatchLimitOne);

            int copyResult = SecItemCopyMatching(query, out IntPtr resultPtr);

            switch (copyResult)
            {
                case OK:
                    return new CFDictionary(resultPtr, true);

                case ErrorSecItemNotFound:
                    return null;

                default:
                    ThrowIfError(copyResult);
                    return null;
            }
        }

        public bool DeleteItem(CFDictionary query)
        {
            query.Add(kSecMatchLimit, kSecMatchLimitOne);

            int deleteResult = SecItemDelete(query.DangerousGetHandle());

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

    public class KeychainRecord
    {
        private readonly CFDictionary _dict;
        private bool _disposed;

        public KeychainRecord(CFDictionary dict)
        {
            _dict = dict;
        }

        public CFDictionary GetAttributes() => _dict;

        protected byte[] GetData(IntPtr key)
        {
            if (_dict.TryGetValue(key, out IntPtr value))
            {
                return new CFData(value, false).ToArray();
            }

            return new byte[0];
        }

        protected string GetString(IntPtr key, string defaultValue = null)
        {
            if (_dict.TryGetValue(key, out IntPtr value))
            {
                return new CFString(value, false).ToString();
            }

            return defaultValue;
        }

        protected long GetNumber(IntPtr key, long defaultValue = 0)
        {
            if (_dict.TryGetValue(key, out IntPtr value))
            {
                return new CFNumber(value, false).GetInt64();
            }

            return defaultValue;
        }

        public byte[] Data => GetData(kSecValueData);

        public string Account => GetString(kSecAttrAccount);

        public string Label => GetString(kSecAttrLabel);

        public string Service => GetString(kSecAttrService);

        //public SecAuthenticationType AuthenticationType { get; set; }

        //public SecProtocolType Protocol { get; set; }

        public string Server => GetString(kSecAttrServer);

        public short Port => (short)GetNumber(kSecAttrPort);

        public string Path => GetString(kSecAttrPath);

        public void Dispose()
        {
            if (_disposed) return;
            _dict.Dispose();
            _disposed = true;
        }
    }

    public class KeychainQuery : CFDictionary
    {
        public KeychainQuery(KeychainItemType type) : base(32)
        {
            Type = type;
        }

        public KeychainItemType Type
        {
            get
            {
                if (this[kSecClass] == kSecClassGenericPassword)
                {
                    return KeychainItemType.GenericPassword;
                }

                if (this[kSecClass] == kSecClassInternetPassword)
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
                        this[kSecClass] = kSecClassGenericPassword;
                        break;

                    case KeychainItemType.InternetPassword:
                        this[kSecClass] = kSecClassInternetPassword;
                        break;

                    default:
                        throw new ArgumentOutOfRangeException(nameof(value));
                }
            }
        }

        public bool ReturnData { get; set; }

        public string Account { get; set; }

        public string Label { get; set; }

        public string Service { get; set; }

        public SecAuthenticationType AuthenticationType { get; set; }

        public SecProtocolType Protocol { get; set; }

        public string Server { get; set; }

        public short Port { get; set; }

        public string Path { get; set; }

        public CFDictionary ToCFDictionary()
        {
            var dict = new CFDictionary(32);

            var x = CoreFoundation.LibraryHandle;
            var y = SecurityFramework.LibraryHandle;

            dict[kSecReturnAttributes] = kCFBooleanTrue;

            if (ReturnData)
            {
                dict[kSecReturnData] = kCFBooleanTrue;
            }

            if (Account != null)
            {
                dict[kSecAttrAccount] = new CFString(Account).DangerousGetHandle();
            }

            if (Label != null)
            {
                dict[kSecAttrLabel] = new CFString(Label).DangerousGetHandle();
            }

            if (Service != null)
            {
                dict[kSecAttrService] = new CFString(Service).DangerousGetHandle();
            }

            if (AuthenticationType != SecAuthenticationType.Any)
            {
                dict[kSecAttrAuthenticationType] = new CFNumber((uint) AuthenticationType).DangerousGetHandle();
            }

            if (Protocol != SecProtocolType.Any)
            {
                dict[kSecAttrProtocol] = new CFNumber((uint) Protocol).DangerousGetHandle();
            }

            if (Server != null)
            {
                dict[kSecAttrServer] = new CFString(Server).DangerousGetHandle();
            }

            if (Port > 0)
            {
                dict[kSecAttrPort] = new CFNumber(Port).DangerousGetHandle();
            }

            if (Path != null)
            {
                dict[kSecAttrPath] = new CFString(Path).DangerousGetHandle();
            }

            return dict;
        }
    }

    public enum KeychainItemType
    {
        GenericPassword,
        InternetPassword
    }
}
