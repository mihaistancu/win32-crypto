using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using ManagedCertificates.Win32;

namespace ManagedCertificates.Revocation
{
    public static class Crl
    {
        public static bool Check(X509Certificate2 certificate)
        {
            bool result = false;

            string[] urlArray = GetCrlUrls(certificate);

            for (int i = 0; i < urlArray.Length; i++)
            {
                IntPtr pCrlContext = DownloadCrl(urlArray[i]);

                if (pCrlContext == IntPtr.Zero) continue;

                result = Verify(certificate.Handle, pCrlContext);

                CAPI.CertFreeCRLContext(pCrlContext);

                break;
            }

            return result;
        }

        private static string[] GetCrlUrls(X509Certificate2 certificate)
        {
            IntPtr pszUrlOid = CAPI.URL_OID_CERTIFICATE_CRL_DIST_POINT;
            IntPtr pvPara = certificate.Handle;
            uint dwFlags = 0;
            IntPtr pUrlArray = IntPtr.Zero;
            uint cbUrlArray = 0;
            IntPtr pUrlInfo = IntPtr.Zero;
            uint cbUrlInfo = 0;
            IntPtr pvReserved = IntPtr.Zero;

            CAPI.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref cbUrlArray, pUrlInfo, ref cbUrlInfo, pvReserved);
            pUrlArray = Marshal.AllocHGlobal((int)cbUrlArray);
            CAPI.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref cbUrlArray, pUrlInfo, ref cbUrlInfo, pvReserved);

            CAPI.CRYPT_URL_ARRAY urlArray = Marshal.PtrToStructure<CAPI.CRYPT_URL_ARRAY>(pUrlArray);
            var urls = MarshalExtensions.PtrToStringArray(urlArray.rgwszUrl, urlArray.cUrl);
            Marshal.FreeHGlobal(pUrlArray);

            return urls;
        }

        private static IntPtr DownloadCrl(string url)
        {
            IntPtr pszObjectOid = CAPI.CONTEXT_OID_CRL;
            uint dwRetrievalFlags = 0;
            uint dwTimeout = 15000;
            IntPtr ppvObject = IntPtr.Zero;
            IntPtr hAsyncRetrieve = IntPtr.Zero;
            IntPtr pCredentials = IntPtr.Zero;
            IntPtr pvVerify = IntPtr.Zero;
            IntPtr pAuxInfo = IntPtr.Zero;

            CAPI.CryptRetrieveObjectByUrl(url, pszObjectOid, dwRetrievalFlags, dwTimeout, ref ppvObject, hAsyncRetrieve, pCredentials, pvVerify, pAuxInfo);

            return ppvObject;
        }

        private static bool Verify(IntPtr pCertContext, IntPtr pCrlContext)
        {
            var certContext = (CAPI.CERT_CONTEXT)Marshal.PtrToStructure(pCertContext, typeof(CAPI.CERT_CONTEXT));
            var crlContext = (CAPI.CRL_CONTEXT)Marshal.PtrToStructure(pCrlContext, typeof(CAPI.CRL_CONTEXT));

            uint dwEncoding = CAPI.PKCS_7_ASN_ENCODING | CAPI.X509_ASN_ENCODING;
            IntPtr pCertId = certContext.pCertInfo;
            uint cCrlInfo = 1;
            IntPtr[] rgpCrlInfo = { crlContext.pCrlInfo };

            return CAPI.CertVerifyCRLRevocation(dwEncoding, pCertId, cCrlInfo, rgpCrlInfo);
        }
    }
}
