using System;
using System.Runtime.InteropServices;
using System.Text;
using Mjcheetham.SecureStorage.Interop;

namespace Mjcheetham.SecureStorage.MacOS.Interop
{
    // https://developer.apple.com/documentation/security/keychain_services/keychain_items
    public static class SecurityFramework
    {
        private const string SecurityFrameworkLib = "/System/Library/Frameworks/Security.framework/Security";

        public static readonly CFNumber kSecMatchLimitAll = new CFNumber(-1);
        public static readonly CFNumber kSecMatchLimitOne = new CFNumber(1);

        public static readonly IntPtr LibraryHandle;

        public static readonly IntPtr kSecClass;
        public static readonly IntPtr kSecMatchLimit;
        public static readonly IntPtr kSecReturnData;
        public static readonly IntPtr kSecReturnAttributes;

        public static readonly IntPtr kSecClassGenericPassword;
        public static readonly IntPtr kSecClassInternetPassword;

        public static readonly IntPtr kSecAttrCreationDate;
        public static readonly IntPtr kSecAttrModificationDate;
        public static readonly IntPtr kSecAttrDescription;
        public static readonly IntPtr kSecAttrComment;
        public static readonly IntPtr kSecAttrCreator;
        public static readonly IntPtr kSecAttrType;
        public static readonly IntPtr kSecAttrLabel;
        public static readonly IntPtr kSecAttrIsInvisible;
        public static readonly IntPtr kSecAttrIsNegative;
        public static readonly IntPtr kSecAttrAccount;
        public static readonly IntPtr kSecAttrService;
        public static readonly IntPtr kSecAttrGeneric;
        public static readonly IntPtr kSecAttrSynchronizable;
        public static readonly IntPtr kSecAttrSecurityDomain;
        public static readonly IntPtr kSecAttrServer;
        public static readonly IntPtr kSecAttrProtocol;
        public static readonly IntPtr kSecAttrAuthenticationType;
        public static readonly IntPtr kSecAttrPort;
        public static readonly IntPtr kSecAttrPath;
        public static readonly IntPtr kSecValueData;

        static SecurityFramework()
        {
            LibraryHandle = LibSystem.dlopen(SecurityFrameworkLib, 0);

            kSecClass                  = LibSystem.GetGlobal(LibraryHandle, "kSecClass");
            kSecMatchLimit             = LibSystem.GetGlobal(LibraryHandle, "kSecMatchLimit");
            kSecReturnData             = LibSystem.GetGlobal(LibraryHandle, "kSecReturnData");
            kSecReturnAttributes       = LibSystem.GetGlobal(LibraryHandle, "kSecReturnAttributes");

            kSecClassGenericPassword   = LibSystem.GetGlobal(LibraryHandle, "kSecClassGenericPassword");
            kSecClassInternetPassword  = LibSystem.GetGlobal(LibraryHandle, "kSecClassInternetPassword");

            kSecAttrCreationDate       = LibSystem.GetGlobal(LibraryHandle, "kSecAttrCreationDate");
            kSecAttrModificationDate   = LibSystem.GetGlobal(LibraryHandle, "kSecAttrModificationDate");
            kSecAttrDescription        = LibSystem.GetGlobal(LibraryHandle, "kSecAttrDescription");
            kSecAttrComment            = LibSystem.GetGlobal(LibraryHandle, "kSecAttrComment");
            kSecAttrCreator            = LibSystem.GetGlobal(LibraryHandle, "kSecAttrCreator");
            kSecAttrType               = LibSystem.GetGlobal(LibraryHandle, "kSecAttrType");
            kSecAttrLabel              = LibSystem.GetGlobal(LibraryHandle, "kSecAttrLabel");
            kSecAttrIsInvisible        = LibSystem.GetGlobal(LibraryHandle, "kSecAttrIsInvisible");
            kSecAttrIsNegative         = LibSystem.GetGlobal(LibraryHandle, "kSecAttrIsNegative");
            kSecAttrAccount            = LibSystem.GetGlobal(LibraryHandle, "kSecAttrAccount");
            kSecAttrService            = LibSystem.GetGlobal(LibraryHandle, "kSecAttrService");
            kSecAttrGeneric            = LibSystem.GetGlobal(LibraryHandle, "kSecAttrGeneric");
            kSecAttrSynchronizable     = LibSystem.GetGlobal(LibraryHandle, "kSecAttrSynchronizable");
            kSecAttrSecurityDomain     = LibSystem.GetGlobal(LibraryHandle, "kSecAttrSecurityDomain");
            kSecAttrServer             = LibSystem.GetGlobal(LibraryHandle, "kSecAttrServer");
            kSecAttrProtocol           = LibSystem.GetGlobal(LibraryHandle, "kSecAttrProtocol");
            kSecAttrAuthenticationType = LibSystem.GetGlobal(LibraryHandle, "kSecAttrAuthenticationType");
            kSecAttrPort               = LibSystem.GetGlobal(LibraryHandle, "kSecAttrPort");
            kSecAttrPath               = LibSystem.GetGlobal(LibraryHandle, "kSecAttrPath");
            kSecValueData              = LibSystem.GetGlobal(LibraryHandle, "kSecValueData");
        }

        [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SecKeychainAddGenericPassword(
            IntPtr keychain,
            uint serviceLength,
            string service,
            uint accountLength,
            string account,
            uint passwordLength,
            byte[] passwordData,
            out IntPtr itemRef);

        [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SecKeychainAddInternetPassword(
            IntPtr keychain,
            uint serverLength,
            string server,
            uint securityDomainLength,
            string securityDomain,
            uint accountLength,
            string account,
            uint pathLength,
            string path,
            ushort port,
            SecProtocolType protocol,
            SecAuthenticationType authenticationType,
            uint passwordLength,
            byte[] passwordData,
            out IntPtr itemRef);

        [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SecKeychainFindGenericPassword(
            IntPtr keychain,
            uint serviceLength,
            string service,
            uint accountLength,
            string account,
            out uint passwordLength,
            out IntPtr passwordData,
            out IntPtr itemRef);

        [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SecKeychainFindInternetPassword(
            IntPtr keychain,
            uint serverLength,
            string server,
            uint securityDomainLength,
            string securityDomain,
            uint accountLength,
            string account,
            uint pathLength,
            string path,
            ushort port,
            SecProtocolType protocol,
            SecAuthenticationType authenticationType,
            out uint passwordLength,
            out IntPtr passwordData,
            out IntPtr itemRef);

        [DllImport(SecurityFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SecKeychainItemCopyAttributesAndData(
            IntPtr itemRef,
            ref SecKeychainAttributeInfo info,
            ref IntPtr itemClass, // SecItemClass*
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
        public static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

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

        // https://developer.apple.com/documentation/security/1542001-security_framework_result_codes
        public const int OK = 0;
        public const int ErrorSecNoSuchKeychain = -25294;
        public const int ErrorSecInvalidKeychain = -25295;
        public const int ErrorSecAuthFailed = -25293;
        public const int ErrorSecDuplicateItem = -25299;
        public const int ErrorSecItemNotFound = -25300;
        public const int ErrorSecInteractionNotAllowed = -25308;
        public const int ErrorSecInteractionRequired = -25315;
        public const int ErrorSecNoSuchAttr = -25303;

        public static void ThrowIfError(int error, string defaultErrorMessage = "Unknown error.")
        {
            switch (error)
            {
                case OK:
                    return;
                case ErrorSecNoSuchKeychain:
                    throw new InteropException("The keychain does not exist.", error);
                case ErrorSecInvalidKeychain:
                    throw new InteropException("The keychain is not valid.", error);
                case ErrorSecAuthFailed:
                    throw new InteropException("Authorization/Authentication failed.", error);
                case ErrorSecDuplicateItem:
                    throw new InteropException("The item already exists.", error);
                case ErrorSecItemNotFound:
                    throw new InteropException("The item cannot be found.", error);
                case ErrorSecInteractionNotAllowed:
                    throw new InteropException("Interaction with the Security Server is not allowed.", error);
                case ErrorSecInteractionRequired:
                    throw new InteropException("User interaction is required.", error);
                case ErrorSecNoSuchAttr:
                    throw new InteropException("The attribute does not exist.", error);
                default:
                    throw new InteropException(defaultErrorMessage, error);
            }
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

    // https://developer.apple.com/documentation/security/secitemattr
    public enum SecKeychainAttrType : uint
    {
        Service = 1937138533,
        Account = 1633903476,
        Label = 1818321516,
        CreationDate = 1667522932,
        ModifiedDate = 1835295092,
    }

    public enum SecProtocolType : uint
    {
        Any          = 0,
        FTP          = 1718906912, // ftp
        FTPAccount   = 1718906977, // ftpa
        HTTP         = 1752462448, // http
        IRC          = 1769104160, // irc
        NNTP         = 1852732528, // nntp
        POP3         = 1886351411, // pop3
        SMTP         = 1936553072, // smtp
        SOCKS        = 1936685088, // sox
        IMAP         = 1768776048, // imap
        LDAP         = 1818517872, // ldap
        AppleTalk    = 1635019883, // atlk
        AFP          = 1634103328, // afp
        Telnet       = 1952803950, // teln
        SSH          = 1936943136, // ssh
        FTPS         = 1718906995, // ftps
        HTTPS        = 1752461427, // htps
        HTTPProxy    = 1752461432, // htpx
        HTTPSProxy   = 1752462200, // htsx
        FTPProxy     = 1718907000, // ftpx
        CIFS         = 1667851891, // cifs
        SMB          = 1936548384, // smb
        RTSP         = 1920234352, // rtsp
        RTSPProxy    = 1920234360, // rtsx
        DAAP         = 1684103536, // daap
        EPPC         = 1701867619, // eppc
        IPP          = 1768976416, // ipp
        NNTPS        = 1853124723, // ntps
        LDAPS        = 1818521715, // ldps
        TelnetS      = 1952803955, // tels
        IMAPS        = 1768779891, // imps
        IRCS         = 1769104243, // ircs
        POP3S        = 1886351475, // pops
        CVSpserver   = 1668707184, // cvsp
        SVN          = 1937141280, // svn
    }

    public enum SecAuthenticationType : uint
    {
        Any        = 0,
        NTLM       = 1853123693, // ntlm
        MSN        = 1836281441, // msna
        DPA        = 1685086561, // dpaa
        RPA        = 1919967585, // rpaa
        HTTPBasic  = 1752462448, // http
        HTTPDigest = 1752462436, // httd
        HTMLForm   = 1718579821, // form
        Default    = 1684434036, // dflt
    }
}
