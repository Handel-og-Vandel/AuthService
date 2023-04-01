using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Controllers
{
    /// <summary>
    /// <link>https://medium.com/geekculture/how-to-add-jwt-authentication-to-an-asp-net-core-api-84e469e9f019</link>
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger, IConfiguration config)
        {
            _config = config;
            _logger = logger;

            _logger.LogInformation($"The secret is: {_config["Secret"]}");
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            // Replace this with your own authentication logic
            if (login.Username != "username" || login.Password != "password")
            {
                return Unauthorized();
            }

            var token = GenerateJwtToken(login.Username);
            return Ok(new { token });
        }

        private string GenerateJwtToken(string username)
        {
            var securityKey = 
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
            
            var credentials = 
                new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username)
            };

            var token = new JwtSecurityToken(
                _config["Issuer"],
                "http://localhost",
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [AllowAnonymous]
        [HttpPost("validate")]
        public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
        {
            if (token.IsNullOrEmpty())
                return BadRequest("Invalid token submited.");

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

        public class LoginModel
        {
            public string? Username { get; set; }
            public string? Password { get; set; }
        }
    }
}

