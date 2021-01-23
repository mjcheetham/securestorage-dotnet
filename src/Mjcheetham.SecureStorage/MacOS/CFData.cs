using System;
using System.Runtime.InteropServices;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    internal class CFData : CFType
    {
        public CFData() : this(new byte[0]) { }

        public CFData(byte[] data)
            : this(CreateHandle(data), true) { }

        public CFData(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public int Length => IsInvalid ? 0 : CFDataGetLength(handle);

        public IntPtr GetBuffer() => CFDataGetBytePtr(handle);

        public byte[] ToArray() => ToArray(handle);

        public static IntPtr CreateHandle(byte[] data)
        {
            return CFDataCreate(kCFAllocatorDefault, data, data.Length);
        }

        public static byte[] ToArray(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                return null;
            }

            int length = CFDataGetLength(handle);
            var buffer = new byte[length];
            IntPtr ptr = CFDataGetBytePtr(handle);
            Marshal.Copy(ptr, buffer, 0, buffer.Length);
            return buffer;
        }
    }
}
