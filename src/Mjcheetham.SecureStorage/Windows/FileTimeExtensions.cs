using System;
using System.Runtime.InteropServices.ComTypes;

namespace Mjcheetham.SecureStorage.Windows
{
    internal static class FileTimeExtensions
    {
        public static DateTime ToDateTime(this FILETIME filetime)
        {
            long ft = (long)filetime.dwHighDateTime << 32 + filetime.dwLowDateTime;
            return DateTime.FromFileTime(ft);
        }

        public static DateTime ToDateTimeUtc(this FILETIME filetime)
        {
            long ft = (long)filetime.dwHighDateTime << 32 + filetime.dwLowDateTime;
            return DateTime.FromFileTimeUtc(ft);
        }
    }
}
