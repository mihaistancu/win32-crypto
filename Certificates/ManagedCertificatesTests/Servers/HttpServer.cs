using System;
using System.Net.Http;
using System.Web.Http;
using Microsoft.Owin.Hosting;
using Owin;

namespace ManagedCertificatesTests.Servers
{
    public class HttpServer : IDisposable
    {
        private readonly HttpConfiguration config;
        private IDisposable server;

        public HttpServer()
        {
            config = new HttpConfiguration();
        }

        public void Setup(string path, HttpMessageHandler handler)
        {
            config.Routes.MapHttpRoute(path, path + "/{*url}", new { url = RouteParameter.Optional }, null, handler);
        }

        public void Start(string baseAddress)
        {
            server = WebApp.Start(baseAddress, appBuilder => appBuilder.UseWebApi(config));
        }

        public void Dispose()
        {
            server?.Dispose();
        }
    }
}
