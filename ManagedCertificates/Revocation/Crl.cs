using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ManagedCertificates.Revocation.Exceptions;
using ManagedCertificates.Win32;

namespace ManagedCertificates.Revocation
{
    public static class Crl
    {
        public static void Check(X509Certificate2 certificate)
        {
            string[] urlArray = GetCrlUrls(certificate);

            foreach (var url in urlArray)
            {
                IntPtr pCrlContext = IntPtr.Zero;

                try
                {
                    pCrlContext = DownloadCrl(url);

                    bool isGood = Verify(certificate.Handle, pCrlContext);

                    if (isGood)
                    {
                        return;
                    }

                    break;
                }
                catch (Exception exception)
                {
                    Console.WriteLine(exception);
                }
                finally
                {
                    CAPI.CertFreeCRLContext(pCrlContext);
                }
            }

            throw new RevocationException(0, 0);
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

            try
            {
                bool result = CAPI.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref cbUrlArray, pUrlInfo, ref cbUrlInfo, pvReserved);
                if (!result)
                {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }

                pUrlArray = Marshal.AllocHGlobal((int) cbUrlArray);

                result = CAPI.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref cbUrlArray, pUrlInfo, ref cbUrlInfo, pvReserved);
                if (!result)
                {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }

                CAPI.CRYPT_URL_ARRAY urlArray = Marshal.PtrToStructure<CAPI.CRYPT_URL_ARRAY>(pUrlArray);
                return MarshalExtensions.PtrToStringArray(urlArray.rgwszUrl, urlArray.cUrl);
            }
            finally
            {
                Marshal.FreeHGlobal(pUrlArray);
            }
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

            var result = CAPI.CryptRetrieveObjectByUrl(url, pszObjectOid, dwRetrievalFlags, dwTimeout, ref ppvObject, hAsyncRetrieve, pCredentials, pvVerify, pAuxInfo);
            if (!result)
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

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
