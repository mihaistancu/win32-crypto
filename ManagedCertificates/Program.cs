using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates
{
    class Program
    {
        static IntPtr GetCertificate(IntPtr hCertStore)
        {
            int dwEncoding = Win32.PKCS_7_ASN_ENCODING | Win32.X509_ASN_ENCODING;
            int dwFindFlags = 0;
            int dwFindType = Win32.CERT_FIND_SUBJECT_STR;
            IntPtr pvFindParam = Marshal.StringToHGlobalUni("leaf");
            IntPtr pPrevCertContext = IntPtr.Zero;

            return Win32.CertFindCertificateInStore(hCertStore, dwEncoding, dwFindFlags, dwFindType, pvFindParam, pPrevCertContext);
        }

        static void Main(string[] args)
        {
            IntPtr hCertStore = Win32.CertOpenSystemStore(IntPtr.Zero, "My");

            IntPtr hCertContext = GetCertificate(hCertStore);
        }
    }
}
