using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using API_Nyous.Contexts;
using API_Nyous.Domains;
using API_Nyous.Utills;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Nyous.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        NyousContext _context = new NyousContext();


        private IConfiguration _config;


        public LoginController(IConfiguration config)
        {
            _config = config;
        }


        private Usuario AuthenticateUser(Usuario login)
        {
            return _context.Usuario.Include(a => a.IdAcessoNavigation).FirstOrDefault(u => u.Email == login.Email && u.Senha == login.Senha);
        }


        private string GenerateJSONWebToken(Usuario userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
        new Claim(JwtRegisteredClaimNames.NameId, userInfo.Nome),
        new Claim(JwtRegisteredClaimNames.Email, userInfo.Email),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(ClaimTypes.Role, userInfo.IdAcessoNavigation.Tipo)
    };


            var token = new JwtSecurityToken
            (
         _config["Jwt:Issuer"],
         _config["Jwt:Issuer"],
         claims,
         expires: DateTime.Now.AddMinutes(120),
         signingCredentials: credentials
              );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] Usuario login)
        {

            login.Senha = Crypto.Criptografar(login.Senha, login.Email.Substring(0, 4));

            IActionResult response = Unauthorized();

            var user = AuthenticateUser(login);
            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }
    }
}