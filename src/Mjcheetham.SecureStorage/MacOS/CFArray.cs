using System;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    public class CFArray : CFType
    {
        public CFArray(int capacity) : base(true)
        {
            SetHandle(
                CFArrayCreateMutable(
                    kCFAllocatorDefault,
                    capacity,
                    kCFTypeArrayCallBacks)
            );
        }

        public CFArray(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public static IntPtr CreateHandle(CFType[] data)
        {
            var cfArrayPtr = CFArrayCreateMutable(
                kCFAllocatorDefault,
                data.Length,
                kCFTypeArrayCallBacks);
            foreach (CFType cfType in data)
            {
                CFArrayAppendValue(cfArrayPtr, cfType.DangerousGetHandle());
            }

            return cfArrayPtr;
        }

        public static CFType[] ToArray(IntPtr handle)
        {
            int count = CFArrayGetCount(handle);
            var array = new CFType[count];
            for (int i = 0; i < count; i++)
            {
                IntPtr valuePtr = CFArrayGetValueAtIndex(handle, i);
                array[i] = CFType.FromHandle(valuePtr, false);
            }

            return array;
        }
    }
}
