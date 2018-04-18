namespace CertificateToolbox
{
    partial class Shell
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

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.save = new System.Windows.Forms.Button();
            this.layout = new System.Windows.Forms.FlowLayoutPanel();
            this.button2 = new System.Windows.Forms.Button();
            this.clear_cache = new System.Windows.Forms.Button();
            this.export = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // save
            // 
            this.save.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.save.Location = new System.Drawing.Point(1161, 12);
            this.save.Name = "save";
            this.save.Size = new System.Drawing.Size(75, 101);
            this.save.TabIndex = 66;
            this.save.Text = "Save";
            this.save.UseVisualStyleBackColor = true;
            this.save.Click += new System.EventHandler(this.save_Click);
            // 
            // layout
            // 
            this.layout.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.layout.AutoScroll = true;
            this.layout.Location = new System.Drawing.Point(12, 12);
            this.layout.Name = "layout";
            this.layout.Size = new System.Drawing.Size(1121, 581);
            this.layout.TabIndex = 68;
            this.layout.WrapContents = false;
            // 
            // button2
            // 
            this.button2.Anchor = System.Windows.Forms.AnchorStyles.Right;
            this.button2.Location = new System.Drawing.Point(1163, 238);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(73, 65);
            this.button2.TabIndex = 69;
            this.button2.Text = "+";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.add_Click);
            // 
            // clear_cache
            // 
            this.clear_cache.Anchor = System.Windows.Forms.AnchorStyles.Right;
            this.clear_cache.Location = new System.Drawing.Point(1163, 345);
            this.clear_cache.Name = "clear_cache";
            this.clear_cache.Size = new System.Drawing.Size(73, 63);
            this.clear_cache.TabIndex = 70;
            this.clear_cache.Text = "Clear CACHE";
            this.clear_cache.UseVisualStyleBackColor = true;
            this.clear_cache.Click += new System.EventHandler(this.clear_cache_Click);
            // 
            // export
            // 
            this.export.Anchor = System.Windows.Forms.AnchorStyles.Right;
            this.export.Location = new System.Drawing.Point(1163, 443);
            this.export.Name = "export";
            this.export.Size = new System.Drawing.Size(73, 63);
            this.export.TabIndex = 71;
            this.export.Text = "Export";
            this.export.UseVisualStyleBackColor = true;
            this.export.Click += new System.EventHandler(this.export_Click);
            // 
            // Shell
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1248, 605);
            this.Controls.Add(this.export);
            this.Controls.Add(this.clear_cache);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.layout);
            this.Controls.Add(this.save);
            this.Name = "Shell";
            this.Text = "Certificate Toolbox";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.Shell_FormClosing);
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.Button save;
        private System.Windows.Forms.FlowLayoutPanel layout;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.Button clear_cache;
        private System.Windows.Forms.Button export;
    }
}

