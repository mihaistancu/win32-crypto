using System;

namespace ManagedCertificates
{
    class Program
    {
        static void Main(string[] args)
        {
            IntPtr hCertStore = Win32.CertOpenSystemStore(IntPtr.Zero, "My");
        }
    }
}
