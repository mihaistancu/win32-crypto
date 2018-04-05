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
            public string[] rgwszUrl;

            public CRYPT_URL_ARRAY(IntPtr pointer)
            {
                cUrl = Marshal.ReadInt16(pointer);
                IntPtr root = Marshal.ReadIntPtr(pointer, Marshal.SizeOf(cUrl));
                IntPtr[] outPointers = new IntPtr[cUrl];
                Marshal.Copy(root, outPointers, 0, cUrl);
                rgwszUrl = new string[cUrl];
                for (int i = 0; i < cUrl; i++)
                {
                    rgwszUrl[i] = Marshal.PtrToStringUni(outPointers[i]);
                }
            }
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

        [DllImport("cryptnet.dll")]
        public static extern bool CryptGetObjectUrl(IntPtr pszUrlOid, IntPtr pvPara, int dwFlags, IntPtr pUrlArray, ref int size, IntPtr pUrlInfo, IntPtr pcbUrlInfo, IntPtr pvReserved);

        [DllImport("cryptnet.dll")]
        public static extern bool CryptRetrieveObjectByUrl(string pszUrl, IntPtr pszObjectOid, int dwRetrievalFlags, int dwTimeout, ref IntPtr ppvObject, IntPtr hAsyncRetrieve, IntPtr pCredentials, IntPtr pvVerify, IntPtr pAuxInfo);

        [DllImport("crypt32.dll")]
        internal static extern void CertFindCertificateInCRL(IntPtr pCertContext, IntPtr pCrlContext, int dwFlags, IntPtr pvReserved, ref IntPtr pCrlEntry);
    }
}