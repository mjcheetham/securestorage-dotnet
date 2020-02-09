using System;
using System.Text;
using Mjcheetham.SecureStorage.MacOS.Interop;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    public class CFString : CFType
    {
        public CFString(string str) : base(true)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(str);

            SetHandle(
                CFStringCreateWithBytes(kCFAllocatorDefault,
                    bytes, bytes.Length,
                    CFStringEncoding.kCFStringEncodingUTF8,
                    false)
            );
        }

        public CFString(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public int Length => IsInvalid ? 0 : CFStringGetLength(handle);

        public override string ToString()
        {
            if (IsInvalid)
            {
                return null;
            }

            int maxSize = CFStringGetMaximumSizeForEncoding(Length, CFStringEncoding.kCFStringEncodingUTF8) + 1;

            byte[] buffer = new byte[maxSize];
            if (CFStringGetCString(handle, buffer, maxSize, CFStringEncoding.kCFStringEncodingUTF8))
            {
                int end = Array.IndexOf(buffer, (byte) 0);
                return Encoding.UTF8.GetString(buffer, 0, end);
            }

            return null;
        }
    }
}
