using System;
using Xunit;

namespace Mjcheetham.SecureStorage.UnitTests
{
    public class MacOSKeychainTests
    {
        [Fact]
        public void MacOSKeychain_ReadWriteDelete()
        {
            MacOSKeychain keychain = MacOSKeychain.OpenDefault();

            const string key = "secretkey";
            const string userName = "john.doe";
            const string password = "letmein123";
            var credential = new Credential(userName, password);

            // Write
            keychain.AddOrUpdate(key, credential);

            // Read
            ICredential outCredential = keychain.Get(key);

            Assert.NotNull(outCredential);
            Assert.Equal(credential.UserName, outCredential.UserName);
            Assert.Equal(credential.Password, outCredential.Password);

            // Delete
            keychain.Remove(key);
        }

        [Fact]
        public void MacOSKeychain_Get_KeyNotFound_ReturnsNull()
        {
            MacOSKeychain keychain = MacOSKeychain.OpenDefault();

            // Unique key; guaranteed not to exist!
            string key = Guid.NewGuid().ToString("N");

            ICredential credential = keychain.Get(key);
            Assert.Null(credential);
        }

        [Fact]
        public void MacOSKeychain_Remove_KeyNotFound_ReturnsFalse()
        {
            MacOSKeychain keychain = MacOSKeychain.OpenDefault();

            // Unique key; guaranteed not to exist!
            string key = Guid.NewGuid().ToString("N");

            bool result = keychain.Remove(key);
            Assert.False(result);
        }
    }
}
