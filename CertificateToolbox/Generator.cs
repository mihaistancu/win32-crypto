using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;
using X509KeyStorageFlags = System.Security.Cryptography.X509Certificates.X509KeyStorageFlags;

namespace CertificateToolbox
{
    public class Generator
    {
        public BigInteger SerialNumber { get; set; }
        public string SubjectName { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public X509Certificate2 Issuer { get; set; }
        public string[] SubjectAlternativeNames { get; set; }
        public string[] Usages { get; set; }
        public bool IsCertificateAuthority { get; set; }
        public string[] OcspEndpoints { get; set; }
        public string[] CrlEndpoints { get; set; }

        private readonly SecureRandom random;
        private readonly X509V3CertificateGenerator certificateGenerator;

        private string issuerName;
        private BigInteger issuerSerialNumber;
        private AsymmetricCipherKeyPair issuerKeyPair;
        private AsymmetricCipherKeyPair subjectKeyPair;
        
        public Generator()
        {
            random = new SecureRandom(new CryptoApiRandomGenerator());
            certificateGenerator = new X509V3CertificateGenerator();
        }

        public X509Certificate2 Generate()
        {
            subjectKeyPair = KeyRepository.Next();
            
            if (Issuer == null)
            {
                issuerKeyPair = subjectKeyPair;
                issuerName = SubjectName;
                issuerSerialNumber = SerialNumber; 
            }
            else
            {
                issuerName = Issuer.Subject;
                issuerKeyPair = DotNetUtilities.GetKeyPair(Issuer.PrivateKey);
                issuerSerialNumber = new BigInteger(Issuer.GetSerialNumber());
            }
            
            certificateGenerator.SetSerialNumber(SerialNumber);
            certificateGenerator.SetSignatureAlgorithm("SHA256WithRSA");
            certificateGenerator.SetIssuerDN(new X509Name(issuerName));
            certificateGenerator.SetSubjectDN(new X509Name(SubjectName));
            certificateGenerator.SetNotBefore(NotBefore);
            certificateGenerator.SetNotAfter(NotAfter);
            certificateGenerator.SetPublicKey(subjectKeyPair.Public);
            AddAuthorityKeyIdentifier();
            AddSubjectKeyIdentifier();
            AddBasicConstraints();
            AddExtendedKeyUsage();
            AddSubjectAlternativeNames();
            AddOcspPoints();
            AddCrlDistributionPoints();

            var certificate = certificateGenerator.Generate(issuerKeyPair.Private);

            return ConvertCertificate(certificate);
        }

        public byte[] GetCrl(RevocationStatus status)
        {
            if (status == RevocationStatus.Unknown | Issuer == null) return new byte[0];

            var generator = new X509V2CrlGenerator();

            generator.SetIssuerDN(new X509Name(Issuer.SubjectName.Name));
            generator.SetThisUpdate(DateTime.Now.AddDays(-1));
            generator.SetNextUpdate(DateTime.Now.AddDays(1));
            generator.SetSignatureAlgorithm("SHA256WithRSA");

            if (status == RevocationStatus.Revoked)
            {
                generator.AddCrlEntry(SerialNumber, DateTime.Now.AddHours(-12), CrlReason.KeyCompromise);
            }

            generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(DotNetUtilities.FromX509Certificate(Issuer)));
            generator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(new BigInteger(new byte[] { 0x01 })));
            var crl = generator.Generate(DotNetUtilities.GetKeyPair(Issuer.PrivateKey).Private);

            return crl.GetEncoded();
        }

        public byte[] GetOcspResponse(RevocationStatus status)
        {
            if (status == RevocationStatus.Unknown | Issuer == null) return new byte[0];

            var bouncyCert = DotNetUtilities.FromX509Certificate(Issuer);
            var gen = new OCSPRespGenerator();

            var basicGen = new BasicOcspRespGenerator(bouncyCert.GetPublicKey());

            basicGen.AddResponse(new CertificateID(CertificateID.HashSha1, bouncyCert, SerialNumber),
                status == RevocationStatus.Revoked
                    ? new RevokedStatus(DateTime.UtcNow, CrlReason.CessationOfOperation)
                    : CertificateStatus.Good);

            var response = basicGen.Generate(basicGen.SignatureAlgNames.Cast<string>().First(), DotNetUtilities.GetKeyPair(Issuer.PrivateKey).Private, new[] { bouncyCert }, DateTime.UtcNow);

            var actualResponse = gen.Generate(0, response);
            return actualResponse.GetEncoded();
        }
        
        private void AddAuthorityKeyIdentifier()
        {
            var authorityKeyIdentifierExtension = new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuerKeyPair.Public), new GeneralNames(new GeneralName(new X509Name(issuerName))), issuerSerialNumber);
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifierExtension);
        }
        
        private void AddSubjectAlternativeNames()
        {
            // Note that you have to repeat the value from the "Subject Name" property.
            if (SubjectAlternativeNames != null && SubjectAlternativeNames.Any())
            {
                var subjectAlternativeNamesExtension = new DerSequence(SubjectAlternativeNames.Select(name => new GeneralName(GeneralName.DnsName, name)).ToArray<Asn1Encodable>());
                certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);
            }
        }
        
        private void AddExtendedKeyUsage()
        {
            if (Usages != null && Usages.Any())
            {
                var usages = Usages.Select(x => x == "client" ? KeyPurposeID.IdKPClientAuth : KeyPurposeID.IdKPServerAuth);
                certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false, new ExtendedKeyUsage(usages));
            }
        }
        
        private void AddBasicConstraints()
        {
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(IsCertificateAuthority));
        }
        
        private void AddSubjectKeyIdentifier()
        {
            var subjectKeyIdentifierExtension = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public));
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, subjectKeyIdentifierExtension);
        }

        public void AddOcspPoints()
        {
            var accessDescriptions = new List<Asn1Encodable>();

            foreach(var endpoint in OcspEndpoints)
            {
                GeneralName generalName = new GeneralName(GeneralName.UniformResourceIdentifier, new DerIA5String(endpoint));
                var accessDescription = new AccessDescription(X509ObjectIdentifiers.OcspAccessMethod, generalName);
                accessDescriptions.Add(accessDescription);
            }

            var seq = new DerSequence(accessDescriptions.ToArray());
            certificateGenerator.AddExtension(X509Extensions.AuthorityInfoAccess, false, seq);
        }

        public void AddCrlDistributionPoints()
        {
            var distributionPoints = new List<Asn1Encodable>();

            foreach(var endpoint in CrlEndpoints)
            {
                var generalName = new GeneralName(GeneralName.UniformResourceIdentifier, new DerIA5String(endpoint));
                var gns = new GeneralNames(generalName);
                var dpn = new DistributionPointName(gns);
                var distp = new DistributionPoint(dpn, null, null);
                distributionPoints.Add(distp);
            }

            var seq = new DerSequence(distributionPoints.ToArray());
            certificateGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false, seq);
        }

        private X509Certificate2 ConvertCertificate(X509Certificate certificate)
        {
            var store = new Pkcs12Store();
            string friendlyName = certificate.SubjectDN.ToString();
            var certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(friendlyName, certificateEntry);
            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(subjectKeyPair.Private), new[] { certificateEntry });

            const string password = "1234";
            var stream = new MemoryStream();
            store.Save(stream, password.ToCharArray(), random);

            return new X509Certificate2(stream.ToArray(), password, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }
    }
}
