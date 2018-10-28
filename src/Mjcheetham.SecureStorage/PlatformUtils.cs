using System;

namespace Mjcheetham.SecureStorage
{
    internal static class PlatformUtils
    {
        public static bool IsMacOS => Environment.OSVersion.Platform == PlatformID.MacOSX;

        public static bool IsWindows => Environment.OSVersion.Platform == PlatformID.Win32NT;

        public static bool IsUnix => Environment.OSVersion.Platform == PlatformID.Unix;

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
