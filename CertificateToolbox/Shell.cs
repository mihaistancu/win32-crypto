using System;
using System.Windows.Forms;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Math;

namespace CertificateToolbox
{
    public partial class Shell : Form
    {
        private BigInteger serialNumber = BigInteger.Zero;

        public Shell()
        {
            InitializeComponent();
        }
        
        public CertificateDetails LastCert
        {
            get { return layout.Controls.Cast<CertificateDetails>().LastOrDefault(); }
        }

        private void save_Click(object sender, EventArgs e)
        {
            save.Enabled = false;

            LastCert?.Generate();

            save.Enabled = true;
        }
        
        private void add_Click(object sender, EventArgs e)
        {
            serialNumber = serialNumber.Add(BigInteger.One);
            var newCert = new CertificateDetails(serialNumber, LastCert);
            newCert.RemoveRequested += Remove;
            layout.Controls.Add(newCert);
        }

        private void Remove(CertificateDetails sender)
        {
            layout.Controls.Remove(sender);

            for (int i = layout.Controls.Count - 1; i > 0; i--)
            {
                ((CertificateDetails)layout.Controls[i]).Issuer = (CertificateDetails)layout.Controls[i - 1];
            }

            if (layout.Controls.Count > 0)
            {
                ((CertificateDetails)layout.Controls[0]).Issuer = null;
            }
        }

        private void Shell_FormClosing(object sender, FormClosingEventArgs e)
        {
            for (int i = layout.Controls.Count - 1; i >= 0; i--)
            {
                ((CertificateDetails)layout.Controls[i]).RemoveExistingCertificate();
            }
        }

        private void clear_cache_Click(object sender, EventArgs e)
        {
            CryptNetCache.Clear();
        }

        private void export_Click(object sender, EventArgs e)
        {
            foreach (CertificateDetails details in layout.Controls)
            {
                var pfxBytes = details.Certificate.Export(X509ContentType.Pkcs12);
                var commonName = details.Certificate.GetNameInfo(X509NameType.SimpleName, false);
                System.IO.File.WriteAllBytes(".\\" + commonName  + ".pfx", pfxBytes);
            }
        }
    }
}
