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
    }
}
