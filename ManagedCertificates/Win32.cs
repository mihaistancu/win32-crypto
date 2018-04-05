using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates
{
    class Win32
    {
        [DllImport("crypt32.dll")]
        public static extern IntPtr CertOpenSystemStore(IntPtr hprov, string szSubsystemProtocol);
    }
}