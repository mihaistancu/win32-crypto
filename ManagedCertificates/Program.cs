using System.Security.Cryptography.X509Certificates;

namespace ManagedCertificates
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.MaxAllowed);
                X509Certificate2 certificate = store.Certificates.Find(X509FindType.FindBySubjectName, "leaf", false)[0];

                bool isOcspValid = Ocsp.Check(certificate);

                bool isCrlValid = Crl.Check(certificate);
            }
        }
    }
}
