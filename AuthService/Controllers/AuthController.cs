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
            
            _logger.LogInformation("Login attempt for user: {}", login.Username);

            try
            {
                if (!login.Username.IsNullOrEmpty() && !login.Password.IsNullOrEmpty())
                {
                    var client = _httpClientFactory.CreateClient();

                    var endpointUrl = _config["UserEndpoint"]! + login.Username;

                    _logger.LogInformation("Retrieving user data from: {}", endpointUrl);

                    var response = await client.GetAsync(endpointUrl);
                    var userJson = await response.Content.ReadAsStringAsync();

                    _logger.LogInformation("User data retrieved: {}", userJson);

                    var user = JsonSerializer.Deserialize<Model.User>(userJson);

                    if (response.IsSuccessStatusCode && user != null )
                    {
                        if (login != null && user.Password == ComputeSHA256Hash(login.Password + user.Salt))
                        {
                            var token = GenerateJwtToken(login.Username!);
                            return Ok(token);
                        }
                    }
                    else
                    {
                        return BadRequest($"Failed to retrieve user: {response.StatusCode}");
                    }
                }
                else
                {
                    return BadRequest("Invalid credentials data.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                return StatusCode(500, $"Internal server error.");
            }

            return Unauthorized();
        }

        /// <summary>
        /// Helping endpoint for validate/debugging a JWT token.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns> <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("validate")]
        public IActionResult ValidateJwtToken([FromBody] string? token)
        {
            if (token.IsNullOrEmpty())
                return BadRequest("No token found in input.");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["Secret"]!);

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

