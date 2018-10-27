using Xunit;

namespace Mjcheetham.SecureStorage.UnitTests
{
    public class MacOSKeychainTests
    {
        [Fact]
        public void MacOSKeychain_ReadWriteDelete()
        {
            MacOSKeychain keychain = MacOSKeychain.OpenDefault();

            const string testKey = "test123";
            const string testValue = "Hello, World!";

            // Write
            keychain.AddOrUpdate(testKey, testValue);

            // Read
            string outputValue = keychain.Get(testKey);

            Assert.Equal(testValue, outputValue);

            // Delete
            keychain.Remove(testKey);
        }
    }
}
