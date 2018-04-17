using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace ManagedCertificates
{
    class Program
    {
        static X509Store OpenStore()
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.MaxAllowed);
            return store;
        }

        static X509Certificate2 GetCertificate(X509Store store)
        {
            return store.Certificates.Find(X509FindType.FindBySubjectName, "leaf", false)[0];
        }
        
        static bool CheckOcsp(X509Certificate2 certificate)
        {
            uint dwEncoding = Win32.PKCS_7_ASN_ENCODING | Win32.X509_ASN_ENCODING;
            uint dwRevType = Win32.CERT_CONTEXT_REVOCATION_TYPE;
            uint cContext = 1;
            IntPtr[] rgpvContext = { certificate.Handle };
            uint dwFlags = Win32.CERT_VERIFY_REV_SERVER_OCSP_FLAG;
            IntPtr pRevPara = IntPtr.Zero;
            var revocationStatus = new Win32.CERT_REVOCATION_STATUS();
            revocationStatus.cbSize = (uint)Marshal.SizeOf(revocationStatus);

            return Win32.CertVerifyRevocation(dwEncoding, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, revocationStatus);
        }

        static string[] GetCrlUrls(X509Certificate2 certificate)
        {
            IntPtr pszUrlOid = Win32.URL_OID_CERTIFICATE_CRL_DIST_POINT;
            IntPtr pvPara = certificate.Handle;
            uint dwFlags = 0;
            IntPtr pUrlArray = IntPtr.Zero;
            uint cbUrlArray = 0;
            IntPtr pUrlInfo = IntPtr.Zero;
            uint cbUrlInfo = 0;
            IntPtr pvReserved = IntPtr.Zero;

            Win32.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref cbUrlArray, pUrlInfo, ref cbUrlInfo, pvReserved);
            pUrlArray = Marshal.AllocHGlobal((int)cbUrlArray);
            Win32.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref cbUrlArray, pUrlInfo, ref cbUrlInfo, pvReserved);

            Win32.CRYPT_URL_ARRAY urlArray = Marshal.PtrToStructure<Win32.CRYPT_URL_ARRAY>(pUrlArray);
            var urls = MarshalExtensions.PtrToStringArray(urlArray.rgwszUrl, urlArray.cUrl);
            Marshal.FreeHGlobal(pUrlArray);

            return urls;
        }

        static IntPtr DownloadCrl(string url)
        {
            IntPtr pszObjectOid = Win32.CONTEXT_OID_CRL;
            uint dwRetrievalFlags = 0;
            uint dwTimeout = 15000;
            IntPtr ppvObject = IntPtr.Zero;
            IntPtr hAsyncRetrieve = IntPtr.Zero;
            IntPtr pCredentials = IntPtr.Zero;
            IntPtr pvVerify = IntPtr.Zero;
            IntPtr pAuxInfo = IntPtr.Zero;

            Win32.CryptRetrieveObjectByUrl(url, pszObjectOid, dwRetrievalFlags, dwTimeout, ref ppvObject, hAsyncRetrieve, pCredentials, pvVerify, pAuxInfo);

            return ppvObject;
        }

        static bool Verify(IntPtr pCertContext, IntPtr pCrlContext)
        {
            var certContext = (Win32.CERT_CONTEXT)Marshal.PtrToStructure(pCertContext, typeof(Win32.CERT_CONTEXT));
            var crlContext = (Win32.CRL_CONTEXT)Marshal.PtrToStructure(pCrlContext, typeof(Win32.CRL_CONTEXT));

            uint dwEncoding = Win32.PKCS_7_ASN_ENCODING | Win32.X509_ASN_ENCODING;
            IntPtr pCertId = certContext.pCertInfo;
            uint cCrlInfo = 1;
            IntPtr[] rgpCrlInfo = new IntPtr[1];
            rgpCrlInfo[0] = crlContext.pCrlInfo;
            
            return Win32.CertVerifyCRLRevocation(dwEncoding, pCertId, cCrlInfo, rgpCrlInfo);
        }

        static bool CheckCrl(X509Certificate2 certificate)
        {
            bool result = false;

            string[] urlArray = GetCrlUrls(certificate);

            for (int i = 0; i < urlArray.Length; i++)
            {
                IntPtr pCrlContext = DownloadCrl(urlArray[i]);

                if (pCrlContext == IntPtr.Zero) continue;

                result = Verify(certificate.Handle, pCrlContext);

                Win32.CertFreeCRLContext(pCrlContext);

                break;
            }

            return result;
        }

        static void Main(string[] args)
        {
            using (var store = OpenStore())
            {
                X509Certificate2 certificate = GetCertificate(store);

                bool isOcspValid = CheckOcsp(certificate);

                bool isCrlValid = CheckCrl(certificate);
            }
        }
    }
}
