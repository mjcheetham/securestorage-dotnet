using System;
using Xunit;

namespace Mjcheetham.SecureStorage.UnitTests
{
    public class WindowsCredentialManagerTests
    {
        [Fact]
        public void WindowsCredentialManager_ReadWriteDelete()
        {
            WindowsCredentialManager credManager = WindowsCredentialManager.OpenDefault();

            const string testKey = "test123";
            const string testValue = "Hello, World!";

            // Write
            credManager.AddOrUpdate(testKey, testValue);

            // Read
            string outputValue = credManager.Get(testKey);

            Assert.Equal(testValue, outputValue);

            // Delete
            credManager.Remove(testKey);
        }
    }
}
