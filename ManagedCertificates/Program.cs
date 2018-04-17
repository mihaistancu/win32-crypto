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
                var certificate = GetCertificate();
                Ocsp.Check(certificate);
                Crl.Check(certificate);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        static X509Certificate2 GetCertificate()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.MaxAllowed);
                return store.Certificates.Find(X509FindType.FindBySubjectName, "leaf", false)[0];
            }
        }
    }
}
