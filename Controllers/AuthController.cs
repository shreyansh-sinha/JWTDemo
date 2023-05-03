using JWTDemo.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace JWTDemo.Controllers
{
    [Route("api/[Controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        [HttpPost("Register")]
        public async Task<IActionResult> Register(UserDTO request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            
            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(UserDTO request)
        {
            if (request.UserName != user.UserName)
                return BadRequest("User not found");

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            var verifyPwd = VerifyPassword(request.Password, passwordHash, passwordSalt);
            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            string token = CreateToken(user);
            return verifyPwd == true ? Ok(token) : Ok("Unauthorized");
        }

        private string CreateToken(User user)
        {
            return string.Empty;
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }    
        }

        private bool VerifyPassword(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                byte[] computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash) ;
            }
        }
    }
}
