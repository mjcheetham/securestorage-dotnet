using System.Collections.Generic;

namespace Mjcheetham.SecureStorage
{
    public interface ISecureStore
    {
        byte[] GetData(string key);

        void SetData(string key, byte[] data);

        bool DeleteData(string key);

        IEnumerable<string> ListKeys();
    }
}
