using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyAuthAPI.Models;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private const string SecretKey = "this_is_a_very_strong_secret_key_123456789";
    private readonly SymmetricSecurityKey _securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginModel model)
    {
        if (model.Username == "admin" && model.Password == "password")
        {
            var token = GenerateJwtToken(model.Username);  // Ensure GenerateJwtToken is in scope
            return Ok(new { token });
        }

        return Unauthorized("Invalid username or password");
    }

    [Authorize]
    [HttpGet("secure-data")]
    public IActionResult GetSecureData()
    {
        return Ok(new { message = "This is a protected route!" });
    }

    private string GenerateJwtToken(string username)  // This method should be here inside the controller
    {
        var credentials = new SigningCredentials(_securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: "yourdomain.com",
            audience: "yourdomain.com",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
