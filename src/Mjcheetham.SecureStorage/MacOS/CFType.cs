using System;
using System.Runtime.InteropServices;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    public abstract class CFType : SafeHandle
    {
        protected CFType(bool ownsHandle) : base(IntPtr.Zero, ownsHandle) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            CFRelease(handle);
            return true;
        }
    }
}
