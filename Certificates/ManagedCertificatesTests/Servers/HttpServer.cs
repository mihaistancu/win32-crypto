using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace ManagedCertificatesTests.Servers
{
    public class HttpServer : IDisposable
    {
        private readonly HttpListener listener;
        private readonly Dictionary<string, Action<HttpListenerResponse>> responseMap;
        private bool stopRequested;

        public List<string> Requests { get; }

        public HttpServer(string baseUrl)
        {
            responseMap = new Dictionary<string, Action<HttpListenerResponse>>();
            Requests = new List<string>();

            listener = new HttpListener();
            listener.Prefixes.Add(baseUrl);
            listener.Start();
            listener.BeginGetContext(ListenerCallback, listener);
        }
        
        public void Setup(string urlPath, string contentType, byte[] content)
        {
            responseMap.Add(urlPath, response =>
            {
                response.ContentType = contentType;
                response.ContentLength64 = content.Length;
                response.OutputStream.Write(content, 0, content.Length);
                response.OutputStream.Close();
                response.Close();
            });
        }

        private void ListenerCallback(IAsyncResult asyncResult)
        {
            if (stopRequested)
            {
                return;
            }

            HttpListenerContext context = listener.EndGetContext(asyncResult);

            var urlPath = context.Request.Url.AbsolutePath;
            var urlResponse = responseMap.First(item => urlPath.StartsWith(item.Key));

            Requests.Add(urlResponse.Key);
            urlResponse.Value(context.Response);

            listener.BeginGetContext(ListenerCallback, listener);
        }

        public void Dispose()
        {
            stopRequested = true;
            listener.Close();
        }
    }
}
