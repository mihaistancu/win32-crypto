using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using ManagedCertificates.Revocation.Exceptions;
using ManagedCertificates.Win32;
using ManagedCertificatesTests.Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ManagedCertificatesTests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            var rootGenerator = new Generator
            {
                IsCertificateAuthority = true
            };
            var root = rootGenerator.Generate();

            var caGenerator = new Generator
            {
                IsCertificateAuthority = true,
                Issuer = root
            };
            var ca = caGenerator.Generate();

            var leafGenerator = new Generator
            {
                Issuer = ca,
                CrlEndpoints = new [] {"http://localhost:9090/crl1", "http://localhost:9090/crl2", "http://localhost:9090/crl3" }
            };
            var leaf = leafGenerator.Generate();
            
        }

        public static void Check(X509Certificate2 certificate)
        {
            uint dwEncoding = CAPI.PKCS_7_ASN_ENCODING | CAPI.X509_ASN_ENCODING;
            uint dwRevType = CAPI.CERT_CONTEXT_REVOCATION_TYPE;
            uint cContext = 1;
            IntPtr[] rgpvContext = { certificate.Handle };
            uint dwFlags = 0;
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
