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

            const string key = "secretkey";
            const string userName = "john.doe";
            const string password = "letmein123";
            var credential = new Credential(userName, password);

            // Write
            credManager.AddOrUpdate(key, credential);

            // Read
            ICredential outCredential = credManager.Get(key);

            Assert.NotNull(outCredential);
            Assert.Equal(credential.UserName, outCredential.UserName);
            Assert.Equal(credential.Password, outCredential.Password);

            // Delete
            credManager.Remove(key);
        }

        [Fact]
        public void WindowsCredentialManager_Get_KeyNotFound_ReturnsNull()
        {
            WindowsCredentialManager credManager = WindowsCredentialManager.OpenDefault();

            // Unique key; guaranteed not to exist!
            string key = Guid.NewGuid().ToString("N");

            ICredential credential = credManager.Get(key);
            Assert.Null(credential);
        }

        [Fact]
        public void WindowsCredentialManager_Remove_KeyNotFound_ReturnsFalse()
        {
            WindowsCredentialManager credManager = WindowsCredentialManager.OpenDefault();

            // Unique key; guaranteed not to exist!
            string key = Guid.NewGuid().ToString("N");

            bool result = credManager.Remove(key);
            Assert.False(result);
        }
    }
}
