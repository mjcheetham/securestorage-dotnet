using System;
using System.Runtime.InteropServices;

namespace Mjcheetham.SecureStorage.Interop
{
    /// <summary>
    /// Marshaler for converting between .NET strings (UTF-16) and byte arrays (UTF-8).
    /// Uses <seealso cref="Utf8StringConverter"/> internally.
    /// </summary>
    public class Utf8StringMarshaler : ICustomMarshaler
    {
        // We need to clean up strings that we marshal to native, but should not clean up strings that
        // we marshal to managed.
        private static readonly Utf8StringMarshaler NativeInstance = new Utf8StringMarshaler(true);
        private static readonly Utf8StringMarshaler ManagedInstance = new Utf8StringMarshaler(false);

        private readonly bool _cleanup;

        public const string NativeCookie  = "U8StringMarshaler.Native";
        public const string ManagedCookie = "U8StringMarshaler.Managed";

        public static ICustomMarshaler GetInstance(string cookie)
        {
            switch (cookie)
            {
                case NativeCookie:
                    return NativeInstance;
                case ManagedCookie:
                    return ManagedInstance;
                default:
                    throw new ArgumentException("Invalid marshaler cookie");
            }
        }

        private Utf8StringMarshaler(bool cleanup)
        {
            _cleanup = cleanup;
        }

        public int GetNativeDataSize()
        {
            return -1;
        }

        public IntPtr MarshalManagedToNative(object value)
        {
            switch (value)
            {
                case null:
                    return IntPtr.Zero;
                case string str:
                    return Utf8StringConverter.ToNative(str);
                default:
                    throw new MarshalDirectiveException("Cannot marshal a non-string");
            }
        }

        public unsafe object MarshalNativeToManaged(IntPtr ptr)
        {
            return Utf8StringConverter.ToManaged((byte*) ptr);
        }

        public void CleanUpManagedData(object value)
        {
        }

        public virtual void CleanUpNativeData(IntPtr ptr)
        {
            if (ptr != IntPtr.Zero && _cleanup)
            {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}
