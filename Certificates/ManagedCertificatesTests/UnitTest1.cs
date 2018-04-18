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
            var generator = new Generator
            {
                IsCertificateAuthority = true
            };
            var root = generator.Generate();
        }
    }
}
