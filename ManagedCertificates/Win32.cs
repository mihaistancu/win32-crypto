using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates
{
    class Win32
    {
        [StructLayout(LayoutKind.Sequential)]
        public class CRYPT_URL_ARRAY
        {
            public int cUrl;
            public IntPtr rgwszUrl;           
        }
        
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

        public static IntPtr URL_OID_CERTIFICATE_CRL_DIST_POINT = new IntPtr(2);
        public static IntPtr CONTEXT_OID_CRL = new IntPtr(2);
        public const int CERT_VERIFY_REV_SERVER_OCSP_FLAG = 0x00000008;
        public const int CERT_CONTEXT_REVOCATION_TYPE = 1;
        public const int X509_ASN_ENCODING = 0x00000001;
        public const int PKCS_7_ASN_ENCODING = 0x00010000;
        
        [DllImport("crypt32.dll")]
        public static extern bool CertVerifyRevocation(int dwEncoding, int dwRevType, int cContext, IntPtr[] rgpvContext, int dwFlags, IntPtr pRevPara, CERT_REVOCATION_STATUS revocationStatus);
        
        [DllImport("cryptnet.dll")]
        public static extern bool CryptGetObjectUrl(IntPtr pszUrlOid, IntPtr pvPara, int dwFlags, IntPtr pUrlArray, ref int size, IntPtr pUrlInfo, IntPtr pcbUrlInfo, IntPtr pvReserved);

        [DllImport("cryptnet.dll")]
        public static extern bool CryptRetrieveObjectByUrl(string pszUrl, IntPtr pszObjectOid, int dwRetrievalFlags, int dwTimeout, ref IntPtr ppvObject, IntPtr hAsyncRetrieve, IntPtr pCredentials, IntPtr pvVerify, IntPtr pAuxInfo);

        [DllImport("crypt32.dll")]
        public static extern void CertFindCertificateInCRL(IntPtr pCertContext, IntPtr pCrlContext, int dwFlags, IntPtr pvReserved, ref IntPtr pCrlEntry);

        [DllImport("crypt32.dll")]
        public static extern void CertFreeCRLContext(IntPtr pCrlContext);
    }
}