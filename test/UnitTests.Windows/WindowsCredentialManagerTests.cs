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
    }
}
