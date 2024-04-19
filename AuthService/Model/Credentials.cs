using System.Text.Json.Serialization;
namespace Model;

/// <summary>
/// Model for incoming login credentials.
/// </summary>
public class Credentials
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }
    [JsonPropertyName("password")]
    public string? Password { get; set; }
}