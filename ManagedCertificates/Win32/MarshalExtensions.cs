using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates.Win32
{
    public static class MarshalExtensions
    {
        // This is needed because structs with variable-sized arrays cannot be marshaled directly
        public static string[] PtrToStringArray(IntPtr pointer, uint arrayLength)
        {
            IntPtr[] outPointers = new IntPtr[arrayLength];
            Marshal.Copy(pointer, outPointers, 0, (int)arrayLength);

            var result = new string[arrayLength];
            for (int i = 0; i < arrayLength; i++)
            {
                result[i] = Marshal.PtrToStringUni(outPointers[i]);
            }
            return result;
        }
    }
}
