using System;
using System.Runtime.InteropServices;

namespace Mjcheetham.SecureStorage.MacOS.Interop
{
    internal static class CoreFoundation
    {
        private const string CoreFoundationFrameworkLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

        public static readonly IntPtr LibraryHandle;

        public static readonly IntPtr kCFBooleanTrue;
        public static readonly IntPtr kCFBooleanFalse;

        public static readonly IntPtr kCFAllocatorDefault;

        public static readonly IntPtr kCFTypeDictionaryKeyCallBacks;
        public static readonly IntPtr kCFTypeDictionaryValueCallBacks;

        public static readonly IntPtr kCFTypeArrayCallBacks;

        static CoreFoundation()
        {
            LibraryHandle = LibSystem.dlopen(CoreFoundationFrameworkLib, 0);

            kCFBooleanTrue  = LibSystem.GetGlobal(LibraryHandle, "kCFBooleanTrue");
            kCFBooleanFalse = LibSystem.GetGlobal(LibraryHandle, "kCFBooleanFalse");

            kCFAllocatorDefault = IntPtr.Zero;

            kCFTypeDictionaryKeyCallBacks   = LibSystem.dlsym(LibraryHandle, "kCFTypeDictionaryKeyCallBacks");
            kCFTypeDictionaryValueCallBacks = LibSystem.dlsym(LibraryHandle, "kCFTypeDictionaryValueCallBacks");

            kCFTypeArrayCallBacks = LibSystem.dlsym(LibraryHandle, "kCFTypeArrayCallBacks");
        }

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint CFGetTypeID(IntPtr cf);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFCopyTypeIDDescription(uint typeId);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint CFDictionaryGetTypeID();

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint CFDataGetTypeID();

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint CFArrayGetTypeID();

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint CFStringGetTypeID();

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint CFNumberGetTypeID();

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFDictionaryCreateMutable(IntPtr allocator, int capacity, IntPtr keyCallbacks, IntPtr valueCallbacks);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFDictionaryAddValue(IntPtr dict, IntPtr key, IntPtr value);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFDictionarySetValue(IntPtr dict, IntPtr key, IntPtr value);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFDictionaryGetKeysAndValues(IntPtr dict, IntPtr[] keys, IntPtr[] values);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFDictionaryGetValue(IntPtr dict, IntPtr key);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFDictionaryGetCount(IntPtr dict);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool CFDictionaryContainsKey(IntPtr dict, IntPtr key);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFRelease(IntPtr cf);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFNumberCreate(IntPtr allocator, CFNumberType type, IntPtr valuePtr);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool CFNumberGetValue(IntPtr number, CFNumberType type, out IntPtr valuePtr);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern CFNumberType CFNumberGetType(IntPtr number);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFStringCreateWithBytes(
            IntPtr allocator,
            byte[] bytes, int numBytes,
            CFStringEncoding encoding,
            bool isExternalRepresentation);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFStringCreateWithCString(IntPtr allocator, byte[] cstr, CFStringEncoding encoding);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFStringGetLength(IntPtr cfString);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool CFStringGetCString(IntPtr cfString, byte[] buffer, int bufferSize, CFStringEncoding encoding);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFStringGetMaximumSizeForEncoding(int length, CFStringEncoding encoding);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, int length);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFDataCreateMutable(IntPtr allocator, int capacity);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFDataAppendBytes(IntPtr theData, byte[] bytes, int length);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFDataGetBytePtr(IntPtr cfData);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFDataGetLength(IntPtr cfData);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFArrayCreateMutable(IntPtr allocator, int capacity, IntPtr callbacks);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFArrayAppendValue(IntPtr theArray, IntPtr value);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFArrayGetCount(IntPtr theArray);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CFArrayGetValueAtIndex(IntPtr theArray, int idx);

        [DllImport(CoreFoundationFrameworkLib, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFArrayGetValues(IntPtr theArray, IntPtr range, IntPtr values);
    }

    public enum CFNumberType
    {
        // Fixed-width types
        SInt8Type = 1,
        SInt16Type = 2,
        SInt32Type = 3,
        SInt64Type = 4,
        Float32Type = 5,
        Float64Type = 6,

        // Basic C types
        CharType = 7,
        ShortType = 8,
        IntType = 9,
        LongType = 10,
        LongLongType = 11,
        FloatType = 12,
        DoubleType = 13,

        // Other
        CFIndexType = 14,
        NSIntegerType  = 15,
        CGFloatType = 16,
        MaxType = 16
    }

    public enum CFStringEncoding
    {
        kCFStringEncodingMacRoman      = 0,
        kCFStringEncodingWindowsLatin1 = 0x0500,
        kCFStringEncodingISOLatin1     = 0x0201,
        kCFStringEncodingNextStepLatin = 0x0B01,
        kCFStringEncodingASCII         = 0x0600,
        kCFStringEncodingUnicode       = 0x0100,
        kCFStringEncodingUTF8          = 0x08000100,
        kCFStringEncodingNonLossyASCII = 0x0BFF,
        kCFStringEncodingUTF16         = 0x0100,
        kCFStringEncodingUTF16BE       = 0x10000100,
        kCFStringEncodingUTF16LE       = 0x14000100,
        kCFStringEncodingUTF32         = 0x0c000100,
        kCFStringEncodingUTF32BE       = 0x18000100,
        kCFStringEncodingUTF32LE       = 0x1c000100
    }
}
