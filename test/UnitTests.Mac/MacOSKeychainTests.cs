using System.Text;
using Xunit;

namespace Mjcheetham.SecureStorage.UnitTests
{
    public class MacOSKeychainTests
    {
        [Fact]
        public void MacOSKeychain_ReadWriteDelete()
        {
            var keychain = MacOSKeychain.OpenDefault();

            string testKey = "test123";
            string testString = "Hello, World!";
            byte[] testData = Encoding.UTF8.GetBytes(testString);

            // Write
            keychain.SetData(testKey, testData);

            // Read
            var outData = keychain.GetData(testKey);
            var outString = Encoding.UTF8.GetString(outData);

            Assert.Equal(testData, outData);
            Assert.Equal(testString, outString);

            // Delete
            keychain.DeleteData(testKey);
        }
    }
}
