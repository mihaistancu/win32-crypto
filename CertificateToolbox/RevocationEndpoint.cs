using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Windows.Forms;

namespace CertificateToolbox
{
    public partial class RevocationEndpoint : UserControl
    {
        private List<HttpListener> listeners;

        public string RevocationType
        {
            get { return groupBox2.Text; }
            set { groupBox2.Text = value; }
        }

        public string[] Urls
        {
            get { return (from DataGridViewRow row in dataGridView1.Rows where row.Cells[0].Value != null select GetUrl(row.Cells[0].Value.ToString())).ToArray(); }
        }

        public string ContentType { get; set; }

        public Func<RevocationStatus, byte[]> GetResponse { get; set; }

        public RevocationEndpoint()
        {
            InitializeComponent();
            listeners = new List<HttpListener>();
            RevocationStatusColumn.DataSource = Enum.GetValues(typeof(RevocationStatus));
            RevocationStatusColumn.ValueType = typeof(RevocationStatus);
        }

        private static int counter = 9090;

        public void Add()
        {
            dataGridView1.Rows.Add(++counter, RevocationStatus.Valid);
        }
        
        public void Start()
        {
            stopRequested = false;

            foreach (DataGridViewRow row in dataGridView1.Rows)
            {
                if (row.Cells[0].Value == null)
                {
                    continue;
                }
                var listener = new HttpListener();
                listeners.Add(listener);
                var baseUrl = GetUrl(row.Cells[0].Value.ToString());
                listener.Prefixes.Add(baseUrl);
                listener.Start();
                listener.BeginGetContext(ListenerCallback, new MyState
                {
                    Listener = listener, GetStatus = ()=>(RevocationStatus)row.Cells[1].Value
                });
            }
        }

        private string GetUrl(string port)
        {
            return string.Format("http://{0}:{1}/", Environment.MachineName, port);
        }

        private bool stopRequested;

        public class MyState
        {
            public HttpListener Listener { get; set; }
            public Func<RevocationStatus> GetStatus { get; set; }
        }

        public void Stop()
        {
            stopRequested = true;
            foreach (var listener in listeners)
            {
                listener.Close();
            }
            listeners.Clear();
        }

        private void ListenerCallback(IAsyncResult asyncResult)
        {
            MyState state = (MyState) asyncResult.AsyncState;
            HttpListener listener = state.Listener;

            try
            {
                if (stopRequested) return;

                HttpListenerContext context = listener.EndGetContext(asyncResult);

                var status = state.GetStatus();
                var response = GetResponse(status);
                context.Response.ContentType = ContentType;
                context.Response.ContentLength64 = response.Length;
                context.Response.OutputStream.Write(response, 0, response.Length);
                context.Response.OutputStream.Close();

                File.AppendAllText("revocation.log", context.Request.Url + status.ToString() + Environment.NewLine);

                context.Response.Close();
            }
            catch (Exception exception)
            {
                MessageBox.Show(exception.ToString());
            }
            finally
            {
                if (!stopRequested)
                {
                    listener.BeginGetContext(ListenerCallback, state);
                }
            }
        }

        private void dataGridView1_DefaultValuesNeeded(object sender, DataGridViewRowEventArgs e)
        {
            e.Row.Cells[0].Value = ++counter;
            e.Row.Cells[1].Value = RevocationStatus.Valid;
        }
    }
}
