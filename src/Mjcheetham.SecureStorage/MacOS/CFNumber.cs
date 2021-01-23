using System;
using System.Runtime.InteropServices;
using Mjcheetham.SecureStorage.MacOS.Interop;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    internal class CFNumber : CFType
    {
        public CFNumber(byte value): this(CreateHandle(value), true)
        {
        }

        public CFNumber(short value): this(CreateHandle(value), true)
        {
        }

        public CFNumber(int value): this(CreateHandle(value), true)
        {
        }

        public CFNumber(long value) : this(CreateHandle(value), true)
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

        public byte GetInt8() => ToInt8(handle);
        public short GetInt16() => ToInt16(handle);
        public int GetInt32() => ToInt32(handle);
        public long GetInt64() => ToInt64(handle);

        public static IntPtr CreateHandle(byte value)
        {
            return CFNumberCreate(
                kCFAllocatorDefault,
                CFNumberType.CharType,
                CreateValuePointer(Marshal.WriteByte, value)
            );
        }

        public static IntPtr CreateHandle(short value)
        {
            return CFNumberCreate(
                kCFAllocatorDefault,
                CFNumberType.ShortType,
                CreateValuePointer(Marshal.WriteInt16, value)
            );
        }

        public static IntPtr CreateHandle(int value)
        {
            return CFNumberCreate(
                kCFAllocatorDefault,
                CFNumberType.IntType,
                CreateValuePointer(Marshal.WriteInt32, value)
            );
        }

        public static IntPtr CreateHandle(long value)
        {
            return CFNumberCreate(
                kCFAllocatorDefault,
                CFNumberType.LongType,
                CreateValuePointer(Marshal.WriteInt64, value)
            );
        }

        public static byte ToInt8(IntPtr handle)
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt8Type, out IntPtr valuePtr))
            {
                return (byte) valuePtr.ToInt32();
            }

            return default;
        }

        public static short ToInt16(IntPtr handle)
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt16Type, out IntPtr valuePtr))
            {
                return (short) valuePtr.ToInt32();
            }

            return default;
        }

        public static int ToInt32(IntPtr handle)
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt32Type, out IntPtr valuePtr))
            {
                return valuePtr.ToInt32();
            }

            return default;
        }

        public static long ToInt64(IntPtr handle)
        {
            if (CFNumberGetValue(handle, CFNumberType.SInt64Type, out IntPtr valuePtr))
            {
                return valuePtr.ToInt64();
            }

            return default;
        }
    }
}
