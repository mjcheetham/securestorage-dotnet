using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mjcheetham.SecureStorage.MacOS;
using Xunit;

namespace Mjcheetham.SecureStorage.UnitTests
{
    public class MacOSKeychainTests
    {
        [Fact]
        public void MacOSKeychain_Test()
        {
            var keychain = new MacOSKeychain();

            using var query = new KeychainQuery(KeychainItemType.InternetPassword)
            {
                Account = "mjcheetham",
                ReturnData = true
            };

            using KeychainItem item = keychain.FindItem(query);

            string account = item.Account;
            string label = item.Label;
            string server = item.Server;
            string service = item.Service;
            string path = item.Path;
            short port = item.Port;
            byte[] data = item.Data;
            string password = Encoding.UTF8.GetString(data);
        }

        [Fact]
        public void MacOSKeychain_FourCharacterCodeConvert()
        {
            var fourCharCodes = new Dictionary<string, string>
            {
                ["FTP         "] = "ftp ",
                ["FTPAccount  "] = "ftpa",
                ["HTTP        "] = "http",
                ["IRC         "] = "irc ",
                ["NNTP        "] = "nntp",
                ["POP3        "] = "pop3",
                ["SMTP        "] = "smtp",
                ["SOCKS       "] = "sox ",
                ["IMAP        "] = "imap",
                ["LDAP        "] = "ldap",
                ["AppleTalk   "] = "atlk",
                ["AFP         "] = "afp ",
                ["Telnet      "] = "teln",
                ["SSH         "] = "ssh ",
                ["FTPS        "] = "ftps",
                ["HTTPS       "] = "htps",
                ["HTTPProxy   "] = "htpx",
                ["HTTPSProxy  "] = "htsx",
                ["FTPProxy    "] = "ftpx",
                ["CIFS        "] = "cifs",
                ["SMB         "] = "smb ",
                ["RTSP        "] = "rtsp",
                ["RTSPProxy   "] = "rtsx",
                ["DAAP        "] = "daap",
                ["EPPC        "] = "eppc",
                ["IPP         "] = "ipp ",
                ["NNTPS       "] = "ntps",
                ["LDAPS       "] = "ldps",
                ["TelnetS     "] = "tels",
                ["IMAPS       "] = "imps",
                ["IRCS        "] = "ircs",
                ["POP3S       "] = "pops",
                ["CVSpserver  "] = "cvsp",
                ["SVN         "] = "svn ",
            };

            var map = new Dictionary<string, (uint, string)>();
            foreach (var kvp in fourCharCodes)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(kvp.Value).Reverse().ToArray();

                try
                {
                    uint dec = BitConverter.ToUInt32(bytes);

                    map[kvp.Key] = (dec, kvp.Value);
                }
                catch (Exception ex)
                {
                    ;
                }
            }

            var sb = new StringBuilder();
            foreach (var kvp in map)
            {
                sb.AppendLine($"{kvp.Key} = {kvp.Value.Item1}, // {kvp.Value.Item2}");
            }

            var ans = sb.ToString();
        }
    }
}
