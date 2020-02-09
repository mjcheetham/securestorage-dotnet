using System;
using System.Runtime.InteropServices;
using Mjcheetham.SecureStorage.Interop;

namespace Mjcheetham.SecureStorage.MacOS.Interop
{
    public static class LibSystem
    {
        private const string Library = "/usr/lib/libSystem.dylib";

        public static readonly IntPtr LibraryHandle;

        static LibSystem()
        {
            LibraryHandle = dlopen(Library, 0);
        }

        public static IntPtr GetGlobal(IntPtr library, string symbol) => GetGlobal<IntPtr>(library, symbol);

        public static T GetGlobal<T>(IntPtr library, string symbol) => dlsym(library, symbol).Dereference<T>();

        [DllImport(Library, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr dlopen (string path, int mode);

        [DllImport(Library, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr dlsym(IntPtr handle, string symbol);
    }
}
