﻿using System;
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

        static IntPtr GetCertificate(X509Store store)
        {
            var certificates = store.Certificates.Find(X509FindType.FindBySubjectName, "leaf", false);
            return certificates[0].Handle;
        }
        
        static bool CheckOcsp(IntPtr pCertContext)
        {
            int dwEncoding = Win32.PKCS_7_ASN_ENCODING | Win32.X509_ASN_ENCODING;
            int dwRevType = Win32.CERT_CONTEXT_REVOCATION_TYPE;
            int cContext = 1;
            IntPtr[] rgpvContext = { pCertContext };
            int dwFlags = Win32.CERT_VERIFY_REV_SERVER_OCSP_FLAG;
            IntPtr pRevPara = IntPtr.Zero;
            var revocationStatus = new Win32.CERT_REVOCATION_STATUS();
            revocationStatus.cbSize = Marshal.SizeOf(revocationStatus);

            return Win32.CertVerifyRevocation(dwEncoding, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, revocationStatus);
        }

        static Win32.CRYPT_URL_ARRAY GetCrlUrls(IntPtr pCertContext)
        {
            IntPtr pszUrlOid = Win32.URL_OID_CERTIFICATE_CRL_DIST_POINT;
            IntPtr pvPara = pCertContext;
            int dwFlags = 0;
            IntPtr pUrlArray = IntPtr.Zero;
            int size = 0;
            IntPtr pUrlInfo = IntPtr.Zero;
            IntPtr pcbUrlInfo = IntPtr.Zero;
            IntPtr pvReserved = IntPtr.Zero;

            Win32.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref size, pUrlInfo, pcbUrlInfo, pvReserved);
            pUrlArray = Marshal.AllocHGlobal(size);
            Win32.CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, ref size, pUrlInfo, pcbUrlInfo, pvReserved);

            return new Win32.CRYPT_URL_ARRAY(pUrlArray);
        }

        static IntPtr DownloadCrl(string url)
        {
            IntPtr pszObjectOid = Win32.CONTEXT_OID_CRL;
            int dwRetrievalFlags = 0;
            int dwTimeout = 15000;
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
            int dwFlags = 0;
            IntPtr pvReserved = IntPtr.Zero;
            IntPtr pCrlEntry = IntPtr.Zero;

            Win32.CertFindCertificateInCRL(pCertContext, pCrlContext, dwFlags, pvReserved, ref pCrlEntry);

            return pCrlEntry == IntPtr.Zero;
        }

        static bool CheckCrl(IntPtr pCertContext)
        {
            bool result = false;

            Win32.CRYPT_URL_ARRAY urlArray = GetCrlUrls(pCertContext);

            for (int i = 0; i < urlArray.cUrl; i++)
            {
                IntPtr pCrlContext = DownloadCrl(urlArray.rgwszUrl[i]);

                if (pCrlContext == IntPtr.Zero) continue;

                result = Verify(pCertContext, pCrlContext);

                Win32.CertFreeCRLContext(pCrlContext);

                break;
            }

            return result;
        }

        static void Main(string[] args)
        {
            using (var store = OpenStore())
            {
                IntPtr pCertContext = GetCertificate(store);

                bool isOcspValid = CheckOcsp(pCertContext);

                bool isCrlValid = CheckCrl(pCertContext);
            }
        }
    }
}
