using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ManagedCertificatesTests.Servers
{
    public class StaticContentHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage response;

        public StaticContentHandler(HttpResponseMessage response)
        {
            this.response = response;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(response);
        }
    }
}
