using System.Text;

namespace Mjcheetham.SecureStorage.Interop
{
    internal static class StringExtensions
    {
        public static byte[] ToByteArray(this string str, Encoding encoding)
        {
            if (string.IsNullOrEmpty(str))
            {
                return new byte[0];
            }
            return encoding.GetBytes(str);
        }
    }
}
