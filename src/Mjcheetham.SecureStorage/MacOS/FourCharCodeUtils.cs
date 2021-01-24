using System;
using System.Linq;
using System.Text;

namespace Mjcheetham.SecureStorage.MacOS
{
    internal static class FourCharCodeUtils
    {
        public static uint ToUInt32(string code)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(code).Reverse().ToArray();
            return BitConverter.ToUInt32(bytes, 0);
        }

        public static string ToString(uint code)
        {
            byte[] bytes = BitConverter.GetBytes(code).Reverse().ToArray();
            return Encoding.UTF8.GetString(bytes);
        }
    }
}
