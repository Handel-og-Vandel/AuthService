


public class EnvironmentVaultRepository : IKeyVaultRepository
{

    Dictionary<string, string> Vault = new Dictionary<string, string>
    {
        {"secret", "sgsklsjhgeyc773h3kxjhcgfdhjskldkjfhgeudc883hj"},
        {"issuer", "DeveloperVault"}
    };

    public EnvironmentVaultRepository()
    {
        
    }

    public Task<string?> GetSecretAsync(string secretName)
    {
        return Task.FromResult<string?>(Vault[secretName]);
    }
}