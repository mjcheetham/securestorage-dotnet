using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Mjcheetham.SecureStorage.Interop
{
    internal static class IntPtrExtensions
    {
        public static T Dereference<T>(this IntPtr ptr)
        {
            return Marshal.PtrToStructure<T>(ptr);
        }

        public static T[] ToStructureArray<T>(this IntPtr ptr, long length) where T : struct
        {
            var structures = new T[length];
            int sizeT = Marshal.SizeOf<T>();

            for (int i = 0; i < length; i++)
            {
                IntPtr structPtr = IntPtr.Add(ptr, sizeT * i);
                structures[i] =  Marshal.PtrToStructure<T>(structPtr);
            }

            return structures;
        }

        public static byte[] ToByteArray(this IntPtr ptr, long length)
        {
            var destination = new byte[length];
            Marshal.Copy(ptr, destination, 0, destination.Length);
            return destination;
        }

        public static string ToString(this IntPtr ptr, long length, Encoding encoding)
        {
            byte[] data = ToByteArray(ptr, length);
            return encoding.GetString(data);
        }
    }
}
