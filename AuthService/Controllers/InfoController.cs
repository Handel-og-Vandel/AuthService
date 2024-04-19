using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    /// <summary>
    /// Controller for handling REST methods on User service.
    /// </summary>
    [Route("api/v1/auth")]
    [ApiController]
    public class InfoController : ControllerBase
    {
        private readonly ILogger _logger;

        public InfoController(ILogger<InfoController> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Service version endpoint. 
        /// Fetches metadata information, through reflection from the service assembly.
        /// </summary>
        /// <returns>All metadata attributes from assembly in text string</returns>
        [HttpGet("version")]
        public async Task<Dictionary<string,string>> GetVersion()
        {
            var properties = new Dictionary<string, string>();
            var assembly = typeof(Program).Assembly;

            properties.Add("service", "HaaV Authentication Service");
            var ver = FileVersionInfo.GetVersionInfo(typeof(Program).Assembly.Location).ProductVersion;
            properties.Add("version", ver!);

            try {
                var hostName = System.Net.Dns.GetHostName();
                var ips = await System.Net.Dns.GetHostAddressesAsync(hostName);
                var ipa = ips.First().MapToIPv4().ToString();
                properties.Add("hosted-at-address", ipa);
            } catch (Exception ex) {
                _logger.LogError(ex.Message);
                properties.Add("hosted-at-address", "Could not resolve IP-address");
            }

            return properties;
        }
    }
}
