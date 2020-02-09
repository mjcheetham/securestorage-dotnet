using System;
using System.Runtime.InteropServices;
using Mjcheetham.SecureStorage.MacOS.Interop;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    public class CFNumber : CFType
    {
        public CFNumber(byte value)
            : this(CFNumberType.CharType, CreateValuePointer(Marshal.WriteByte, value))
        {
        }

        public CFNumber(short value)
            : this(CFNumberType.ShortType, CreateValuePointer(Marshal.WriteInt16, value))
        {
        }

        public CFNumber(int value)
            : this(CFNumberType.IntType, CreateValuePointer(Marshal.WriteInt32, value))
        {
        }

        public CFNumber(long value)
            : this(CFNumberType.LongType, CreateValuePointer(Marshal.WriteInt64, value))
        {
        }

        public CFNumber(CFNumberType type, IntPtr value) : base(true)
        {
            SetHandle(CFNumberCreate(kCFAllocatorDefault, type, value));
        }

        public CFNumber(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        private static IntPtr CreateValuePointer<T>(Action<IntPtr, T> writeFunc, T value)
        {
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(value));
            writeFunc(ptr, value);
            return ptr;
        }

        public CFNumberType NumberType => CFNumberGetType(handle);

        public byte GetInt8()
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt8Type, out IntPtr valuePtr))
            {
                return (byte) valuePtr.ToInt32();
            }

            return default;
        }

        public short GetInt16()
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt16Type, out IntPtr valuePtr))
            {
                return (short) valuePtr.ToInt32();
            }

            return default;
        }

        public int GetInt32()
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt32Type, out IntPtr valuePtr))
            {
                return valuePtr.ToInt32();
            }

            return default;
        }

        public long GetInt64()
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt64Type, out IntPtr valuePtr))
            {
                return valuePtr.ToInt64();
            }

            return default;
        }
    }
}
