using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;
using Org.BouncyCastle.Math;

namespace CertificateToolbox
{
    public partial class CertificateDetails : UserControl
    {
        public X509Certificate2 Certificate { get; set; }
        public CertificateDetails Issuer { get; set; }

        private readonly BigInteger serialNo;

        public CertificateDetails()
        {
            InitializeComponent();
        }

        public CertificateDetails(BigInteger serialNumber, CertificateDetails issuer)
        {
            InitializeComponent();

            Issuer = issuer;

            serialNo = serialNumber;
            serial.Text = serialNumber.ToString();
            subject.Text = string.Format("CN={0} {1}", Environment.MachineName, serialNumber);

            store_name.DataSource = Enum.GetValues(typeof(StoreName));
            store_name.SelectedItem = StoreName.Root;

            store_location.DataSource = Enum.GetValues(typeof(StoreLocation));
            store_location.SelectedItem = StoreLocation.LocalMachine;

            not_before.Value = DateTime.UtcNow.AddDays(-1);
            not_after.Value = DateTime.UtcNow.AddYears(100);

            subject_alternative_names.ReadOnly = is_ca.Checked;
            key_usages.ReadOnly = is_ca.Checked;
            
            ocsp.Add();
            ocsp.GetResponse = GetOcsp;

            crl.Add();
            crl.GetResponse = GetCrl;
        }
        
        private byte[] GetCrl(RevocationStatus status)
        {
            var generator = new Generator
            {
                Issuer = Issuer == null ? Certificate : Issuer.Certificate,
                SerialNumber = serialNo,
            };
            return generator.GetCrl(status);
        }

        private byte[] GetOcsp(RevocationStatus status)
        {
            var generator = new Generator
            {
                Issuer = Issuer == null ? Certificate : Issuer.Certificate,
                SerialNumber = serialNo,
            };
            return generator.GetOcspResponse(status);
        }
        
        public X509Certificate2 Generate()
        {
            StopRevocationServers();

            RemoveExistingCertificate();

            ClearThumbprint();

            GenerateCertificate();

            if (install_store.Checked)
            {
                InstallNewCertificate();
            }

            UpdateThumbprint();

            StartRevocationServers();

            return Certificate;
        }

        public void RemoveExistingCertificate()
        {
            if (string.IsNullOrEmpty(thumbprint.Text)) return;

            foreach (StoreLocation storeLocation in new [] {StoreLocation.LocalMachine, StoreLocation.CurrentUser})
            foreach (StoreName storeName in Enum.GetValues(typeof(StoreName)))
            {
                var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite | OpenFlags.MaxAllowed);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint.Text, false);
                if (certificates.Count == 1)
                {
                    store.Remove(certificates[0]);
                }
                store.Close();
            }
        }

        private void InstallNewCertificate()
        {
            var store = new X509Store((StoreName)store_name.SelectedItem, (StoreLocation)store_location.SelectedItem);
            store.Open(OpenFlags.ReadWrite);
            store.Add(Certificate);
            store.Close();
        }

        private void GenerateCertificate()
        {
            var generator = new Generator
            {
                SerialNumber = new BigInteger(serial.Text),
                SubjectName = subject.Text,
                NotBefore = not_before.Value,
                NotAfter = not_after.Value,
                IsCertificateAuthority = is_ca.Checked,
                Issuer = Issuer?.Generate(),
                SubjectAlternativeNames = Serialize(subject_alternative_names.Rows),
                Usages = Serialize(key_usages.Rows),
                OcspEndpoints = ocsp.Urls,
                CrlEndpoints = crl.Urls
            };

            Certificate = generator.Generate();
        }
        
        private string[] Serialize(DataGridViewRowCollection rows)
        {
            return (from DataGridViewRow row in rows where row.Cells[0].Value != null select row.Cells[0].Value.ToString()).ToArray();
        }

        private void ClearThumbprint()
        {
            thumbprint.Clear();
            Refresh();
        }

        private void UpdateThumbprint()
        {
            thumbprint.Text = Certificate.Thumbprint;
            Refresh();
        }

        private void StartRevocationServers()
        {
            ocsp.Start();
            crl.Start();
        }
        
        private void StopRevocationServers()
        {
            ocsp.Stop();
            crl.Stop();
        }

        private void is_ca_CheckedChanged(object sender, EventArgs e)
        {
            subject_alternative_names.ReadOnly = is_ca.Checked;
            key_usages.ReadOnly = is_ca.Checked;

            if (is_ca.Checked)
            {
                subject_alternative_names.Rows.Clear();
                key_usages.Rows.Clear();
            }
        }

        public event Action<CertificateDetails> RemoveRequested;

        private void remove_Click(object sender, EventArgs e)
        {
            RemoveExistingCertificate();
            StopRevocationServers();
            RemoveRequested?.Invoke(this);
        }
        
        private void copy_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(thumbprint.Text);
        }
    }
}
