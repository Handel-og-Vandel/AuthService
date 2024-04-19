using System.Text.Json.Serialization;

namespace Model;

public class User
{
    [JsonPropertyName("id")]
    public Guid Id { get; set; }
    [JsonPropertyName("firstName")]
    public string? GivenName { get; set; }
    [JsonPropertyName("FamilyName")]
    public string? FamilyName { get; set; }
    [JsonPropertyName("department")]
    public string? Department { get; set; }
    [JsonPropertyName("password")]
    public string? Password { get; set; }
    [JsonPropertyName("email")]
    public string? Email { get; set; }
    [JsonPropertyName("loginIdentifier")]
    public string? LoginIdentifier { get; set; }
    [JsonPropertyName("salt")]
    public string? Salt { get; set; }
}