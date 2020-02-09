using System;
using Mjcheetham.SecureStorage.Windows;
using Xunit;

namespace Mjcheetham.SecureStorage.UnitTests
{
    public class WindowsCredentialManagerTests
    {
        [Fact]
        public void WindowsCredentialManager_ReadWriteDelete()
        {
            WindowsCredentialManager credManager = WindowsCredentialManager.Open();

            const string targetName = "secretkey";
            const string userName = "john.doe";
            const string password = "letmein123";
            var credential = new WindowsCredential(targetName, userName, password);

            // Write
            credManager.Write(credential);

            // Read
            WindowsCredential outCredential = credManager.Read(targetName);

            Assert.NotNull(outCredential);
            Assert.Equal(credential.UserName, outCredential.UserName);
            Assert.Equal(credential.Password, outCredential.Password);

            // Delete
            credManager.Delete(targetName);
        }

        [Fact]
        public void WindowsCredentialManager_Read_KeyNotFound_ReturnsNull()
        {
            WindowsCredentialManager credManager = WindowsCredentialManager.Open();

            // Unique key; guaranteed not to exist!
            string key = Guid.NewGuid().ToString("N");

            WindowsCredential credential = credManager.Read(key);
            Assert.Null(credential);
        }

        [Fact]
        public void WindowsCredentialManager_Delete_KeyNotFound_ReturnsFalse()
        {
            WindowsCredentialManager credManager = WindowsCredentialManager.Open();

            // Unique key; guaranteed not to exist!
            string key = Guid.NewGuid().ToString("N");

            bool result = credManager.Delete(key);
            Assert.False(result);
        }
    }
}
