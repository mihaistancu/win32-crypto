using System;
using System.Security.Cryptography.X509Certificates;
using ManagedCertificates.Revocation;

namespace ManagedCertificates
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.MaxAllowed);
                    X509Certificate2 certificate = store.Certificates.Find(X509FindType.FindBySubjectName, "leaf", false)[0];

                    Ocsp.Check(certificate);

                    bool isCrlValid = Crl.Check(certificate);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
