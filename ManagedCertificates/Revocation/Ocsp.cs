using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using ManagedCertificates.Revocation.Exceptions;
using ManagedCertificates.Win32;

namespace ManagedCertificates.Revocation
{
    public static class Ocsp
    {
        public static void Check(X509Certificate2 certificate)
        {
            uint dwEncoding = CAPI.PKCS_7_ASN_ENCODING | CAPI.X509_ASN_ENCODING;
            uint dwRevType = CAPI.CERT_CONTEXT_REVOCATION_TYPE;
            uint cContext = 1;
            IntPtr[] rgpvContext = { certificate.Handle };
            uint dwFlags = CAPI.CERT_VERIFY_REV_SERVER_OCSP_FLAG;
            IntPtr pRevPara = IntPtr.Zero;
            var revocationStatus = new CAPI.CERT_REVOCATION_STATUS(Marshal.SizeOf(typeof(CAPI.CERT_REVOCATION_STATUS)));

            bool isGood = CAPI.CertVerifyRevocation(dwEncoding, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, revocationStatus);

            if (!isGood)
            {
                throw new RevocationException(revocationStatus.dwError, revocationStatus.dwReason);
            }
        }
    }
}
