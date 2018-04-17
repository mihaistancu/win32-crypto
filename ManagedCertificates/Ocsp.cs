using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace ManagedCertificates
{
    public static class Ocsp
    {
        public static bool Check(X509Certificate2 certificate)
        {
            uint dwEncoding = Win32.PKCS_7_ASN_ENCODING | Win32.X509_ASN_ENCODING;
            uint dwRevType = Win32.CERT_CONTEXT_REVOCATION_TYPE;
            uint cContext = 1;
            IntPtr[] rgpvContext = { certificate.Handle };
            uint dwFlags = Win32.CERT_VERIFY_REV_SERVER_OCSP_FLAG;
            IntPtr pRevPara = IntPtr.Zero;
            var revocationStatus = new Win32.CERT_REVOCATION_STATUS(Marshal.SizeOf(typeof(Win32.CERT_REVOCATION_STATUS)));

            return Win32.CertVerifyRevocation(dwEncoding, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, revocationStatus);
        }
    }
}
