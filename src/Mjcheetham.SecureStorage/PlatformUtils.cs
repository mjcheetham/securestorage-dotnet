using System;
using System.Runtime.InteropServices;

namespace Mjcheetham.SecureStorage
{
    internal static class PlatformUtils
    {
        public static bool IsMacOS => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        public static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static bool IsUnix => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        public static void EnsureMacOS()
        {
            if (!IsMacOS)
            {
                throw new PlatformNotSupportedException();
            }
        }

        public static void EnsureWindows()
        {
            if (!IsWindows)
            {
                throw new PlatformNotSupportedException();
            }
        }

        public static void EnsureUnix()
        {
            if (!IsUnix)
            {
                throw new PlatformNotSupportedException();
            }
        }
    }
}
