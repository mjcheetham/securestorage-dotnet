using System;
using System.Runtime.InteropServices;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    public class CFData : CFType
    {
        public CFData() : this(new byte[0]) { }

        public CFData(byte[] data) : base(true)
        {
            SetHandle(
                CFDataCreate(kCFAllocatorDefault, data, data.Length)
            );
        }

        public CFData(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public int Length => IsInvalid ? 0 : CFDataGetLength(handle);

        public IntPtr GetBuffer() => CFDataGetBytePtr(handle);

        public byte[] ToArray()
        {
            if (IsInvalid)
            {
                return null;
            }

            var buffer = new byte[Length];
            IntPtr ptr = GetBuffer();
            Marshal.Copy(ptr, buffer, 0, buffer.Length);
            return buffer;
        }
    }
}
