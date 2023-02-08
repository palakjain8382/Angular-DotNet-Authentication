using AuthenticationAPI.Data;
using AuthenticationAPI.Helpers;
using AuthenticationAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Client;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

namespace AuthenticationAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly ApplicationDbContext _db;

        public UserController(ApplicationDbContext db)
        {
            _db = db;
        }

        [HttpPost("authenticate")]
       public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _db.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username);
            if(user == null)
                return NotFound(new {Message = "User Not Found!"});

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message = "Incorrect Password " });
            }


            user.Token = createJwtToken(user);
            return Ok(new {
                Token = user.Token,
                Message = "Login Success!"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            //check email
            if (await CheckEmailExistsAsync(userObj.Email))
                return BadRequest(new { Message = "Email Already Exists!" });

            //Check username
            if (await CheckUsernameExistsAsync(userObj.Username))
                return BadRequest(new { Message = "Username Already Exists!" });

            //check pw strength
            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _db.Users.AddAsync(userObj);
            await _db.SaveChangesAsync();
            return Ok(new {Message = "User Registered!"});
        }

        private Task<bool> CheckUsernameExistsAsync(string username)
            => _db.Users.AnyAsync(x => x.Username == username);

        private Task<bool> CheckEmailExistsAsync(string email)
    => _db.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]")))
                sb.Append("Password must contain small letters" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[A-Z]")))
                sb.Append("Password must contain capital letters" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password must contain numbers" + Environment.NewLine);
            if(!(Regex.IsMatch(password, "[\\W]")))
                sb.Append("Password must contain special characters" + Environment.NewLine);
            return sb.ToString();
        }

        private string createJwtToken(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("mySecretKey........");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.UtcNow.AddSeconds(5),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        [HttpGet]
        //[Authorize]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _db.Users.ToListAsync());
        }
    }
}
