using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ManagedCertificates.Win32;
using ManagedCertificatesTests.Certificates;
using ManagedCertificatesTests.Servers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Math;

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

            using (var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.MaxAllowed);
                store.Add(root);
            }

            using (var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.MaxAllowed);
                store.Add(ca);
            }

            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.MaxAllowed);
                store.Add(leaf);
            }

            var generator = new Generator
            {
                Issuer = ca,
                SerialNumber = new BigInteger(leaf.SerialNumber, 16)
            };

            using (var server = new HttpServer("http://localhost:9090/"))
            {
                server.Setup("/crl1", "application/pkix-crl", generator.GetCrl(RevocationStatus.Unknown));
                server.Setup("/crl2", "application/pkix-crl", generator.GetCrl(RevocationStatus.Valid));
                server.Setup("/crl3", "application/pkix-crl", generator.GetCrl(RevocationStatus.Unknown));
                
                CryptNetCache.Clear();

                Check(leaf);
            }

        }

        private void Check(X509Certificate2 certificate)
        {
            uint dwEncoding = CAPI.PKCS_7_ASN_ENCODING | CAPI.X509_ASN_ENCODING;
            uint dwRevType = CAPI.CERT_CONTEXT_REVOCATION_TYPE;
            uint cContext = 1;
            IntPtr[] rgpvContext = { certificate.Handle };
            uint dwFlags = 0;
            IntPtr pRevPara = IntPtr.Zero;
            var revocationStatus = new CAPI.CERT_REVOCATION_STATUS(Marshal.SizeOf(typeof(CAPI.CERT_REVOCATION_STATUS)));

            bool isGood = CAPI.CertVerifyRevocation(dwEncoding, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, revocationStatus);

            var result = new CryptographicException((int)revocationStatus.dwError);
        }
    }
}
