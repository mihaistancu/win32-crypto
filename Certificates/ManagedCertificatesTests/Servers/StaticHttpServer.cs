using System;
using System.Collections.Generic;
using System.Net.Http;

namespace ManagedCertificatesTests.Servers
{
    public class StaticHttpServer
    {
        public static IDisposable Start(string baseAddress, Dictionary<string, HttpResponseMessage> config)
        {
            var server = new HttpServer();
            foreach (var item in config)
            {
                server.Setup(item.Key, new StaticContentHandler(item.Value));
            }
            server.Start(baseAddress);
            return server;
        }
    }
}
