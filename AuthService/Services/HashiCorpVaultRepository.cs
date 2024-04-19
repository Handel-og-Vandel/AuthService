using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;

public class HashiCorpVaultRepository : IKeyVaultRepository
{
    private readonly ILogger<HashiCorpVaultRepository> _logger;
    private readonly string _vaultBaseUrl;
    private readonly string _vaultPath;
    private readonly string _vaultMountPoint;
    private readonly IVaultClient _vaultClient;

    
    public HashiCorpVaultRepository(ILogger<HashiCorpVaultRepository> logger, IConfiguration configuration)
    {
        _logger = logger;

        _vaultBaseUrl = configuration["VaultURL"] ?? "https://localhost:8201/";
        _vaultPath = configuration["VaultPath"] ?? "<Not defined>";
        _vaultMountPoint = configuration["VaultMountPoint"] ?? "<not defined>";
        
        var httpClientHandler = new HttpClientHandler();
        httpClientHandler.ServerCertificateCustomValidationCallback = 
                (message, cert, chain, sslPolicyErrors) => { return true; };
        
        IAuthMethodInfo authMethod = 
            new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

        var vaultClientSettings = new VaultClientSettings(_vaultBaseUrl, authMethod)
        {
            Namespace = "",
            MyHttpClientProviderFunc = handler 
                => new HttpClient(httpClientHandler) { 
                    BaseAddress = new Uri(_vaultBaseUrl) 
                }
        };
        
        _vaultClient = new VaultClient(vaultClientSettings);

        _logger.LogInformation($"Connected to Vault server at {_vaultBaseUrl}");
        _logger.LogInformation($"  using path : {_vaultPath}");
        _logger.LogInformation($"        mount: {_vaultMountPoint}");
        
    }

    public async Task<string?> GetSecretAsync(string secretName)
    {
        string? secretValue = null;

        try
        {
            Secret<SecretData> theSecret = 
                await _vaultClient.V1.Secrets.KeyValue.V2
                               .ReadSecretAsync(path: _vaultPath, 
                                                mountPoint: _vaultMountPoint);
            secretValue = theSecret.Data.Data[secretName].ToString();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Failed to get secret {secretName} from vault server");
        }

        return secretValue;
    }
}

