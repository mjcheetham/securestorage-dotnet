using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static Mjcheetham.SecureStorage.MacOS.Interop.CoreFoundation;

namespace Mjcheetham.SecureStorage.MacOS
{
    internal class CFDictionary : CFType, IDictionary<IntPtr, IntPtr>
    {
        public CFDictionary(int capacity) : base(true)
        {
            SetHandle(
                CFDictionaryCreateMutable(
                    kCFAllocatorDefault,
                    capacity,
                    kCFTypeDictionaryKeyCallBacks,
                    kCFTypeDictionaryValueCallBacks)
            );
        }

        public CFDictionary(IntPtr handle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(handle);
        }

        public CFDictionary(IDictionary<IntPtr, IntPtr> dict) : this(dict.Count)
        {
            foreach (var kvp in dict)
            {
                Add(kvp);
            }
        }

        public IEnumerator<KeyValuePair<IntPtr, IntPtr>> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public void Add(KeyValuePair<IntPtr, IntPtr> item) => CFDictionaryAddValue(handle, item.Key, item.Value);

        public void Clear()
        {
            throw new NotImplementedException();
        }

        public bool Contains(KeyValuePair<IntPtr, IntPtr> item) =>
            TryGetValue(item.Key, out IntPtr value) && value == item.Value;

        public void CopyTo(KeyValuePair<IntPtr, IntPtr>[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public bool Remove(KeyValuePair<IntPtr, IntPtr> item)
        {
            throw new NotImplementedException();
        }

        public int Count => CFDictionaryGetCount(handle);

        public bool IsReadOnly => false;

        public void Add(IntPtr key, IntPtr value) => CFDictionaryAddValue(handle, key, value);

        public void Add(IntPtr key, SafeHandle value) => CFDictionaryAddValue(handle, key, value.DangerousGetHandle());

        public bool ContainsKey(IntPtr key) => CFDictionaryContainsKey(handle, key);

        public bool Remove(IntPtr key)
        {
            throw new NotImplementedException();
        }

        public bool TryGetValue(IntPtr key, out IntPtr value)
        {
            if (ContainsKey(key))
            {
                value = CFDictionaryGetValue(handle, key);
                return true;
            }

            value = IntPtr.Zero;
            return false;
        }

        public IntPtr this[IntPtr key]
        {
            get => CFDictionaryGetValue(handle, key);
            set => CFDictionarySetValue(handle, key, value);
        }

        public void SetValue(IntPtr key, IntPtr value) => CFDictionarySetValue(handle, key, value);

        public void SetValue(IntPtr key, SafeHandle value) => CFDictionarySetValue(handle, key, value.DangerousGetHandle());

        public ICollection<IntPtr> Keys
        {
            get
            {
                var keys = new IntPtr[Count];
                var values = new IntPtr[Count];
                CFDictionaryGetKeysAndValues(handle, keys, values);
                return keys;
            }
        }

        public ICollection<IntPtr> Values
        {
            get
            {
                var keys = new IntPtr[Count];
                var values = new IntPtr[Count];
                CFDictionaryGetKeysAndValues(handle, keys, values);
                return values;
            }
        }

        protected override bool ReleaseHandle()
        {
            CFRelease(handle);
            return true;
        }

        public string GetString(IntPtr key)
        {
            return TryGetValue(key, out IntPtr ptr) ? CFString.ToString(ptr) : null;
        }

        public void SetString(IntPtr key, string value)
        {
            if (value is null)
            {
                Remove(key);
            }
            else
            {
                SetValue(key, CFString.CreateHandle(value));
            }
        }
    }
}
