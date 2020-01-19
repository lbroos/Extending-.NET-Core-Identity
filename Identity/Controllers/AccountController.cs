using Identity.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Controllers
{
    [Route("api/account")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser<Guid>> _userManager;
        private readonly IdentityContext _context;
        private readonly SignInManager<IdentityUser<Guid>> _signInManager;
        private readonly IConfiguration _configuration;

        public AccountController(
            UserManager<IdentityUser<Guid>> userManager, 
            IdentityContext context, 
            SignInManager<IdentityUser<Guid>> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _context = context;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);

            if (!result.Succeeded)
            {
                return BadRequest("Username / password are not correct");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var appUser = await _userManager.Users.SingleOrDefaultAsync(u => u.Email == model.Email);
            var roles = await _userManager.GetRolesAsync(appUser);
            var token = GenerateJwtToken(model.Email, appUser, roles);
            string role = string.Empty;
            if (roles.Count != 0)
            {
                if (roles.Contains("Admin"))
                {
                    role = "Admin";
                }
                else
                {
                    role = "User";
                }
            }

            return Ok(new
            {
                Username = appUser.UserName,
                Token = token
            });
        }

        private object GenerateJwtToken(string email, IdentityUser<Guid> user, IList<string> roles)
        {
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));
            var signingCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddDays(Convert.ToDouble(1));
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.UserData, user.Id.ToString())
            };

            foreach (string role in roles)
            {
                Claim claim = new Claim(ClaimTypes.Role, role);
                claims.Add(claim);
            }

            var token = new JwtSecurityToken(
                _configuration["JWT:Issuer"],
                _configuration["JWT:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: signingCredentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}