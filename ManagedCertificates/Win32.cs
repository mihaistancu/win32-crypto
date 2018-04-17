using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates
{
    class Win32
    {
        internal const string CRYPT32 = "crypt32.dll";
        internal const string CRYPTNET = "cryptnet.dll";

        public static readonly IntPtr URL_OID_CERTIFICATE_CRL_DIST_POINT = new IntPtr(2);
        public static readonly IntPtr CONTEXT_OID_CRL = new IntPtr(2);
        public const uint CERT_VERIFY_REV_SERVER_OCSP_FLAG = 0x00000008;
        public const uint CERT_CONTEXT_REVOCATION_TYPE = 1;
        public const uint X509_ASN_ENCODING = 0x00000001;
        public const uint PKCS_7_ASN_ENCODING = 0x00010000;
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CERT_CONTEXT
        {
            internal uint dwCertEncodingType;
            internal IntPtr pbCertEncoded;
            internal uint cbCertEncoded;
            internal IntPtr pCertInfo;
            internal IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRL_CONTEXT
        {
            internal uint dwCertEncodingType;
            internal IntPtr pbCrlEncoded;
            internal uint cbCrlEncoded;
            internal IntPtr pCrlInfo;
            internal IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class CRYPT_URL_ARRAY
        {
            public uint cUrl;
            public IntPtr rgwszUrl;           
        }
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class CERT_REVOCATION_STATUS
        {
            public CERT_REVOCATION_STATUS(int size)
            {
                cbSize = (uint)size;
                dwIndex = 0;
                dwError = 0;
                dwReason = 0;
                fHasFreshnessTime = false;
                dwFreshnessTime = 0;
            }

            public uint cbSize;
            public uint dwIndex;
            public uint dwError;
            public uint dwReason;
            public bool fHasFreshnessTime;
            public uint dwFreshnessTime;
        }
        
        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CertVerifyRevocation(uint dwEncoding, uint dwRevType, uint cContext, IntPtr[] rgpvContext, uint dwFlags, IntPtr pRevPara, CERT_REVOCATION_STATUS revocationStatus);

        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CertVerifyCRLRevocation(uint dwEncoding, IntPtr pCertId, uint cCrlInfo, IntPtr[] rgpCrlInfo);

        [DllImport(CRYPTNET, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptGetObjectUrl(IntPtr pszUrlOid, IntPtr pvPara, uint dwFlags, IntPtr pUrlArray, ref uint pcbUrlArray, IntPtr pUrlInfo, ref uint pcbUrlInfo, IntPtr pvReserved);

        [DllImport(CRYPTNET, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CryptRetrieveObjectByUrl(string pszUrl, IntPtr pszObjectOid, uint dwRetrievalFlags, uint dwTimeout, ref IntPtr ppvObject, IntPtr hAsyncRetrieve, IntPtr pCredentials, IntPtr pvVerify, IntPtr pAuxInfo);
        
        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern void CertFreeCRLContext(IntPtr pCrlContext);
    }
}