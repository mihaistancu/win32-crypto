using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates
{
    public static class MarshalExtensions
    {
        public static string[] PtrToStringArray(IntPtr pointer, int arrayLength)
        {
            IntPtr[] outPointers = new IntPtr[arrayLength];
            Marshal.Copy(pointer, outPointers, 0, arrayLength);

            var result = new string[arrayLength];
            for (int i = 0; i < arrayLength; i++)
            {
                result[i] = Marshal.PtrToStringAuto(outPointers[i]);
            }
            return result;
        }
    }
}
