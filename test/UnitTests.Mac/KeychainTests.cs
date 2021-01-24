using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mjcheetham.SecureStorage.MacOS;
using Mjcheetham.SecureStorage.MacOS.Interop;
using Xunit;

namespace Mjcheetham.SecureStorage.UnitTests
{
    public class KeychainTests
    {
        [Fact]
        public void Keychain_Test()
        {
            var keychain = new Keychain();

            using var query = new KeychainItem(KeychainItemType.InternetPassword)
            {
                Account = "mjcheetham"
            };

            using IKeychainItem item = keychain.FindItem(query, false);

            using var newItem = new KeychainItem(KeychainItemType.GenericPassword)
            {
                Account = "alice",
                Service = "git:example.com",
                Label = "test-test-test"
            };

            SecProtocolType proto = item.Protocol;

            keychain.AddItem(newItem);

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
        public void Keychain_FourCharacterCodeConvert()
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
