namespace CertificateToolbox
{
    partial class CertificateDetails
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.not_after = new System.Windows.Forms.DateTimePicker();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.KeyUsage = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.key_usages = new System.Windows.Forms.DataGridView();
            this.SubjectAlternativeName = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.subject_alternative_names = new System.Windows.Forms.DataGridView();
            this.is_ca = new System.Windows.Forms.CheckBox();
            this.not_before = new System.Windows.Forms.DateTimePicker();
            this.install_store = new System.Windows.Forms.CheckBox();
            this.subject = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.store_name = new System.Windows.Forms.ComboBox();
            this.label10 = new System.Windows.Forms.Label();
            this.serial = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.thumbprint = new System.Windows.Forms.TextBox();
            this.remove = new System.Windows.Forms.Button();
            this.copy = new System.Windows.Forms.Button();
            this.crl = new CertificateToolbox.RevocationEndpoint();
            this.ocsp = new CertificateToolbox.RevocationEndpoint();
            this.store_location = new System.Windows.Forms.ComboBox();
            ((System.ComponentModel.ISupportInitialize)(this.key_usages)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.subject_alternative_names)).BeginInit();
            this.SuspendLayout();
            // 
            // not_after
            // 
            this.not_after.Location = new System.Drawing.Point(17, 270);
            this.not_after.Name = "not_after";
            this.not_after.Size = new System.Drawing.Size(222, 20);
            this.not_after.TabIndex = 53;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(16, 254);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(49, 13);
            this.label3.TabIndex = 65;
            this.label3.Text = "Not After";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(16, 203);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(58, 13);
            this.label2.TabIndex = 64;
            this.label2.Text = "Not Before";
            // 
            // KeyUsage
            // 
            this.KeyUsage.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.Fill;
            this.KeyUsage.HeaderText = "Key Usage";
            this.KeyUsage.Name = "KeyUsage";
            this.KeyUsage.Resizable = System.Windows.Forms.DataGridViewTriState.True;
            // 
            // key_usages
            // 
            this.key_usages.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.key_usages.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.KeyUsage});
            this.key_usages.Location = new System.Drawing.Point(19, 484);
            this.key_usages.Name = "key_usages";
            this.key_usages.Size = new System.Drawing.Size(265, 124);
            this.key_usages.TabIndex = 56;
            // 
            // SubjectAlternativeName
            // 
            this.SubjectAlternativeName.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.Fill;
            this.SubjectAlternativeName.HeaderText = "Subject Alternative Name";
            this.SubjectAlternativeName.Name = "SubjectAlternativeName";
            // 
            // subject_alternative_names
            // 
            this.subject_alternative_names.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.subject_alternative_names.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.SubjectAlternativeName});
            this.subject_alternative_names.Location = new System.Drawing.Point(19, 354);
            this.subject_alternative_names.Name = "subject_alternative_names";
            this.subject_alternative_names.Size = new System.Drawing.Size(265, 124);
            this.subject_alternative_names.TabIndex = 55;
            // 
            // is_ca
            // 
            this.is_ca.AutoSize = true;
            this.is_ca.Checked = true;
            this.is_ca.CheckState = System.Windows.Forms.CheckState.Checked;
            this.is_ca.Location = new System.Drawing.Point(19, 320);
            this.is_ca.Name = "is_ca";
            this.is_ca.Size = new System.Drawing.Size(128, 17);
            this.is_ca.TabIndex = 54;
            this.is_ca.Text = "Is Certificate Authority";
            this.is_ca.UseVisualStyleBackColor = true;
            this.is_ca.CheckedChanged += new System.EventHandler(this.is_ca_CheckedChanged);
            // 
            // not_before
            // 
            this.not_before.Location = new System.Drawing.Point(19, 219);
            this.not_before.Name = "not_before";
            this.not_before.Size = new System.Drawing.Size(220, 20);
            this.not_before.TabIndex = 52;
            // 
            // install_store
            // 
            this.install_store.AutoSize = true;
            this.install_store.Checked = true;
            this.install_store.CheckState = System.Windows.Forms.CheckState.Checked;
            this.install_store.Location = new System.Drawing.Point(19, 12);
            this.install_store.Name = "install_store";
            this.install_store.Size = new System.Drawing.Size(92, 17);
            this.install_store.TabIndex = 61;
            this.install_store.Text = "Install in Store";
            this.install_store.UseVisualStyleBackColor = true;
            // 
            // subject
            // 
            this.subject.Location = new System.Drawing.Point(19, 168);
            this.subject.Name = "subject";
            this.subject.Size = new System.Drawing.Size(220, 20);
            this.subject.TabIndex = 51;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(16, 152);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(140, 13);
            this.label1.TabIndex = 57;
            this.label1.Text = "Subject Distinguished Name";
            // 
            // store_name
            // 
            this.store_name.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.store_name.FormattingEnabled = true;
            this.store_name.Location = new System.Drawing.Point(118, 10);
            this.store_name.Name = "store_name";
            this.store_name.Size = new System.Drawing.Size(121, 21);
            this.store_name.TabIndex = 49;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Location = new System.Drawing.Point(16, 103);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(73, 13);
            this.label10.TabIndex = 58;
            this.label10.Text = "Serial Number";
            // 
            // serial
            // 
            this.serial.Location = new System.Drawing.Point(19, 119);
            this.serial.Name = "serial";
            this.serial.Size = new System.Drawing.Size(220, 20);
            this.serial.TabIndex = 50;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(16, 62);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(60, 13);
            this.label4.TabIndex = 67;
            this.label4.Text = "Thumbprint";
            // 
            // thumbprint
            // 
            this.thumbprint.Location = new System.Drawing.Point(19, 78);
            this.thumbprint.Name = "thumbprint";
            this.thumbprint.ReadOnly = true;
            this.thumbprint.Size = new System.Drawing.Size(220, 20);
            this.thumbprint.TabIndex = 66;
            // 
            // remove
            // 
            this.remove.Location = new System.Drawing.Point(257, 12);
            this.remove.Name = "remove";
            this.remove.Size = new System.Drawing.Size(44, 23);
            this.remove.TabIndex = 68;
            this.remove.Text = "X";
            this.remove.UseVisualStyleBackColor = true;
            this.remove.Click += new System.EventHandler(this.remove_Click);
            // 
            // copy
            // 
            this.copy.Location = new System.Drawing.Point(257, 78);
            this.copy.Name = "copy";
            this.copy.Size = new System.Drawing.Size(44, 23);
            this.copy.TabIndex = 68;
            this.copy.Text = "Copy";
            this.copy.UseVisualStyleBackColor = true;
            this.copy.Click += new System.EventHandler(this.copy_Click);
            // 
            // crl
            // 
            this.crl.ContentType = "application/pkix-crl";
            this.crl.GetResponse = null;
            this.crl.Location = new System.Drawing.Point(9, 762);
            this.crl.Name = "crl";
            this.crl.RevocationType = "CRL";
            this.crl.Size = new System.Drawing.Size(292, 133);
            this.crl.TabIndex = 69;
            // 
            // ocsp
            // 
            this.ocsp.ContentType = "application/ocsp-response";
            this.ocsp.GetResponse = null;
            this.ocsp.Location = new System.Drawing.Point(9, 614);
            this.ocsp.Name = "ocsp";
            this.ocsp.RevocationType = "OCSP";
            this.ocsp.Size = new System.Drawing.Size(292, 142);
            this.ocsp.TabIndex = 69;
            // 
            // store_location
            // 
            this.store_location.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.store_location.FormattingEnabled = true;
            this.store_location.Location = new System.Drawing.Point(118, 37);
            this.store_location.Name = "store_location";
            this.store_location.Size = new System.Drawing.Size(121, 21);
            this.store_location.TabIndex = 70;
            // 
            // CertificateDetails
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.store_location);
            this.Controls.Add(this.crl);
            this.Controls.Add(this.ocsp);
            this.Controls.Add(this.copy);
            this.Controls.Add(this.remove);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.thumbprint);
            this.Controls.Add(this.not_after);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.key_usages);
            this.Controls.Add(this.subject_alternative_names);
            this.Controls.Add(this.is_ca);
            this.Controls.Add(this.not_before);
            this.Controls.Add(this.install_store);
            this.Controls.Add(this.subject);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.store_name);
            this.Controls.Add(this.label10);
            this.Controls.Add(this.serial);
            this.Name = "CertificateDetails";
            this.Size = new System.Drawing.Size(323, 899);
            ((System.ComponentModel.ISupportInitialize)(this.key_usages)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.subject_alternative_names)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.DateTimePicker not_after;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.DataGridViewTextBoxColumn KeyUsage;
        private System.Windows.Forms.DataGridView key_usages;
        private System.Windows.Forms.DataGridViewTextBoxColumn SubjectAlternativeName;
        private System.Windows.Forms.DataGridView subject_alternative_names;
        private System.Windows.Forms.CheckBox is_ca;
        private System.Windows.Forms.DateTimePicker not_before;
        private System.Windows.Forms.CheckBox install_store;
        private System.Windows.Forms.TextBox subject;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.ComboBox store_name;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.TextBox serial;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox thumbprint;
        private System.Windows.Forms.Button remove;
        private System.Windows.Forms.Button copy;
        private RevocationEndpoint ocsp;
        private RevocationEndpoint crl;
        private System.Windows.Forms.ComboBox store_location;
    }
}
