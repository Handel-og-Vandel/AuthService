

/// <summary>
/// Implementation used for development and testing purposes.
/// All secrets are stored in a dictionary.
/// Uses default values if not found in environment configuration.
/// </summary>
public class EnvironmentVaultRepository : IKeyVaultRepository
{

    Dictionary<string, string> Vault = new Dictionary<string, string>
    {
        {"secret", "sgsklsjhgeyc773h3kxjhcgfdhjskldkjfhgeudc883hj"},
        {"issuer", "DeveloperVault"}
    };

    public EnvironmentVaultRepository(
        ILogger<EnvironmentVaultRepository> logger, 
        IConfiguration configuration)
    {
        var secret = configuration["Secret"];
        var issuer = configuration["Issuer"];
        if (secret != null)
        {
            Vault["secret"] = secret;
        }
        if (issuer != null) 
        {
            Vault["issuer"] = issuer;
        }
    }

    public Task<string?> GetSecretAsync(string secretName)
    {
        return Task.FromResult<string?>(Vault[secretName]);
    }
}