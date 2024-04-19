public interface IKeyVaultRepository
{
    Task<string?> GetSecretAsync(string secretName);
}
