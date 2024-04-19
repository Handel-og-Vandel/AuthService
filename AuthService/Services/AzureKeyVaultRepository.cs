using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

public class AzureKeyVaultRepository : IKeyVaultRepository
{
    private readonly string keyVaultUri;
    private readonly SecretClient secretClient;

    public AzureKeyVaultRepository(string keyVaultUri)
    {
        this.keyVaultUri = keyVaultUri;
        secretClient = new SecretClient(new Uri(keyVaultUri), new DefaultAzureCredential());
    }

    public async Task<string?> GetSecretAsync(string secretName)
    {
        try
        {
            KeyVaultSecret secret = await secretClient.GetSecretAsync(secretName);
            return secret.Value;
        }
        catch (RequestFailedException ex)
        {
            // Handle exception (e.g., secret not found, access denied)
            Console.WriteLine($"Error getting secret: {ex.Message}");
            return null;
        }
    }
}