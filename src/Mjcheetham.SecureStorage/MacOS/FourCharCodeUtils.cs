using System;
using System.Linq;
using System.Text;

namespace Mjcheetham.SecureStorage.MacOS
{
    internal static class FourCharCodeUtils
    {
        public static uint ToUInt32(byte[] code)
        {
            return BitConverter.ToUInt32(code, 0);
        }

        public static uint ToUInt32(string code)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(code).Reverse().ToArray();
            return ToUInt32(bytes);
        }

        public static string ToString(byte[] code)
        {
            return Encoding.UTF8.GetString(code);
        }

        public static string ToString(uint code)
        {
            byte[] bytes = BitConverter.GetBytes(code).Reverse().ToArray();
            return ToString(bytes);
        }

        public static byte[] ToBytes(string code)
        {
            return Encoding.UTF8.GetBytes(code).Reverse().ToArray();
        }

        public static byte[] ToBytes(uint code)
        {
            return BitConverter.GetBytes(code).Reverse().ToArray();
        }
    }
}
