using System;
using System.Text;
using Mjcheetham.SecureStorage.MacOS.Interop;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    internal class CFString : CFType
    {
        public CFString(string str) : base(true)
        {
            SetHandle(CreateHandle(str));
        }

        public CFString(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public int Length => IsInvalid ? 0 : CFStringGetLength(handle);

        public override string ToString()
        {
            return ToString(handle);
        }

        public static IntPtr CreateHandle(string str)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(str);

            return CFStringCreateWithBytes(kCFAllocatorDefault,
                bytes, bytes.Length,
                CFStringEncoding.kCFStringEncodingUTF8,
                false);
        }

        public static string ToString(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }

            int length = CFStringGetLength(ptr);
            int maxSize = CFStringGetMaximumSizeForEncoding(length, CFStringEncoding.kCFStringEncodingUTF8) + 1;

            byte[] buffer = new byte[maxSize];
            if (CFStringGetCString(ptr, buffer, maxSize, CFStringEncoding.kCFStringEncodingUTF8))
            {
                int end = Array.IndexOf(buffer, (byte) 0);
                return Encoding.UTF8.GetString(buffer, 0, end);
            }

            return null;
        }
    }
}
