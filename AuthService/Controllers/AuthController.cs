using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Model;
using System.Security.Cryptography;

namespace AuthService.Controllers
{
    /// <summary>
    /// Authentication for identity provider in HaaV infrastructure.
    /// </summary>
    [Route("api/v1/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;
        private readonly IKeyVaultRepository _secrets;
        private readonly IHttpClientFactory _httpClientFactory;

        /// <summary>
        /// Create instance of AuthController.
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="config"></param>
        /// <param name="secrets"></param>
        /// <param name="httpClientFactory"></param>
        public AuthController(ILogger<AuthController> logger, IConfiguration config, 
                                IKeyVaultRepository secrets, IHttpClientFactory httpClientFactory)
        {
            _config = config;
            _logger = logger;
            _secrets = secrets;
            _httpClientFactory = httpClientFactory;
        }

        /// <summary>
        /// Handle user credentials and return a JWT token.
        /// </summary>
        /// <param name="login">User credentials</param>
        /// <returns>JWT token on credentials accepted</returns> 
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Credentials login)
        {
            if (!login.Username.IsNullOrEmpty() && !login.Password.IsNullOrEmpty())
            {
                var user = await GetUserData(login);
               
                if (user != null) {
                    if (user.Password == ComputeSHA256Hash(login.Password + user.Salt))
                    {
                        var token = GenerateJwtToken(login.Username!);
                        _logger.LogInformation("User {username} logged in.", login.Username);
                        return Ok(token);
                    }
                    else
                    {
                        _logger.LogWarning("User {username} failed to login.", login.Username);
                        return Unauthorized();
                    }
                }
                else
                {
                    return BadRequest($"Failed to retrieve user data for {login.Username}.");
                }
            }
            else
            {
                return BadRequest("Invalid credentials data.");
            }
        }

        private async Task<User?> GetUserData(Credentials login)
        {
            var endpointUrl = _config["UserEndpoint"]! + login.Username;
            _logger.LogInformation("Retrieving user data from: {}", endpointUrl);
            
            var client = _httpClientFactory.CreateClient();
            HttpResponseMessage response;

            try {
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                response = await client.GetAsync(endpointUrl);
            } catch (Exception ex) {
                _logger.LogError(ex, ex.Message);
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                try {
                    string? userJson = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<User>(userJson);
                } catch (Exception ex) {
                    _logger.LogError(ex, ex.Message);
                    return null;
                }
            }
            return null;
        }

        /// <summary>
        /// Helping endpoint for validate/debugging a JWT token.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("validate")]
        public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
        {
            if (token.IsNullOrEmpty())
                return BadRequest("No token found in input.");

            var tokenHandler = new JwtSecurityTokenHandler();
            var secret = await _secrets.GetSecretAsync("secret");
            
            if (secret.IsNullOrEmpty())
                throw new Exception("Secret not found in vault.");

            var key = Encoding.ASCII.GetBytes(secret!);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;

                var accountId = jwtToken.Claims.First(
                    x => x.Type == ClaimTypes.NameIdentifier).Value;

                // return account id from JWT token if validation successful
                return Ok(accountId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                return StatusCode(404);
            }
        }

        private async Task<string> GenerateJwtToken(string username)
        {
            var secret = await _secrets.GetSecretAsync("secret");
            var issuer = await _secrets.GetSecretAsync("issuer");

            if (secret.IsNullOrEmpty() || issuer.IsNullOrEmpty())
                throw new Exception("Secret or issuer not found in vault.");

            var securityKey = 
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret!));
            
            var credentials = 
                new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username)
            };

            var token = new JwtSecurityToken(
                issuer,
                "http://localhost",
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string ComputeSHA256Hash(string rawData)
        {
            byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawData));

            StringBuilder builder = new();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }

    }
}

