using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    public abstract class CFType : SafeHandle
    {
        private static readonly IDictionary<uint, Func<IntPtr, bool, CFType>> TypeCtorFuncs =
            new Dictionary<uint, Func<IntPtr, bool, CFType>>();

        static CFType()
        {
            TypeCtorFuncs[CFArrayGetTypeID()]      = (ptr, owns) => new CFArray     (ptr, owns);
            TypeCtorFuncs[CFDataGetTypeID()]       = (ptr, owns) => new CFData      (ptr, owns);
            TypeCtorFuncs[CFDictionaryGetTypeID()] = (ptr, owns) => new CFDictionary(ptr, owns);
            TypeCtorFuncs[CFNumberGetTypeID()]     = (ptr, owns) => new CFNumber    (ptr, owns);
            TypeCtorFuncs[CFStringGetTypeID()]     = (ptr, owns) => new CFString    (ptr, owns);
        }

        protected CFType(bool ownsHandle) : base(IntPtr.Zero, ownsHandle) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            CFRelease(handle);
            return true;
        }

        protected static CFType FromHandle(IntPtr cf, bool ownsHandle)
        {
            uint typeId = CFGetTypeID(cf);
            if (TypeCtorFuncs.TryGetValue(typeId, out Func<IntPtr, bool, CFType> ctor))
            {
                return ctor(cf, ownsHandle);
            }

            string typeName = CFString.ToString(CFCopyTypeIDDescription(typeId));
            throw new Exception($"Unknown CFTypeID {typeId} ({typeName})");
        }
    }
}
