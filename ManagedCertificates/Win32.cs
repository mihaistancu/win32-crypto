using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates
{
    class Win32
    {
        [StructLayout(LayoutKind.Sequential)]
        public class CERT_REVOCATION_STATUS
        {
            public int cbSize;
            public int dwIndex;
            public int dwError;
            public int dwReason;
            public bool fHasFreshnessTime;
            public int dwFreshnessTime;
        }

        public const int CERT_VERIFY_REV_SERVER_OCSP_FLAG = 0x00000008;
        public const int CERT_CONTEXT_REVOCATION_TYPE = 1;
        public const int CERT_FIND_SUBJECT_STR = 0x00080007;
        public const int X509_ASN_ENCODING = 0x00000001;
        public const int PKCS_7_ASN_ENCODING = 0x00010000;

        [DllImport("crypt32.dll")]
        public static extern IntPtr CertOpenSystemStore(IntPtr hprov, string szSubsystemProtocol);

        [DllImport("crypt32.dll")]
        public static extern IntPtr CertFindCertificateInStore(IntPtr hCertStore, int dwEncoding, int dwFindFlags, int dwFindType, IntPtr pvFindParam, IntPtr pPrevCertContext);

        [DllImport("crypt32.dll")]
        public static extern bool CertVerifyRevocation(int dwEncoding, int dwRevType, int cContext, IntPtr[] rgpvContext, int dwFlags, IntPtr pRevPara, CERT_REVOCATION_STATUS revocationStatus);

        [DllImport("crypt32.dll")]
        public static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        [DllImport("crypt32.dll")]
        public static extern bool CertCloseStore(IntPtr hCertStore, int dwFlags);
    }
}