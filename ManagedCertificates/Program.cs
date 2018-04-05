using System;
using System.Runtime.InteropServices;

namespace ManagedCertificates
{
    class Program
    {
        static IntPtr GetCertificate(IntPtr hCertStore)
        {
            int dwEncoding = Win32.PKCS_7_ASN_ENCODING | Win32.X509_ASN_ENCODING;
            int dwFindFlags = 0;
            int dwFindType = Win32.CERT_FIND_SUBJECT_STR;
            IntPtr pvFindParam = Marshal.StringToHGlobalUni("leaf");
            IntPtr pPrevCertContext = IntPtr.Zero;

            return Win32.CertFindCertificateInStore(hCertStore, dwEncoding, dwFindFlags, dwFindType, pvFindParam, pPrevCertContext);
        }

        static Win32.CERT_REVOCATION_STATUS GetEmptyRevocationStatus()
        {
            var revocationStatus = new Win32.CERT_REVOCATION_STATUS();
            revocationStatus.cbSize = Marshal.SizeOf(revocationStatus);
            return revocationStatus;
        }

        static bool CheckOcsp(IntPtr pCertContext)
        {
            int dwEncoding = Win32.PKCS_7_ASN_ENCODING | Win32.X509_ASN_ENCODING;
            int dwRevType = Win32.CERT_CONTEXT_REVOCATION_TYPE;
            int cContext = 1;
            IntPtr[] rgpvContext = { pCertContext };
            int dwFlags = Win32.CERT_VERIFY_REV_SERVER_OCSP_FLAG;
            IntPtr pRevPara = IntPtr.Zero;
            Win32.CERT_REVOCATION_STATUS revocationStatus = GetEmptyRevocationStatus();
            
            return Win32.CertVerifyRevocation(dwEncoding, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, revocationStatus);
        }

        static void Main(string[] args)
        {
            IntPtr hCertStore = Win32.CertOpenSystemStore(IntPtr.Zero, "My");

            IntPtr pCertContext = GetCertificate(hCertStore);

            bool isOcspValid = CheckOcsp(pCertContext);

            Win32.CertFreeCertificateContext(pCertContext);

            Win32.CertCloseStore(hCertStore, 0);
        }
    }
}
