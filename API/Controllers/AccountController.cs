using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly DataContext _contxt;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext contxt, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _contxt = contxt;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDTO register){
            if (await UserExist(register.UserName)) return BadRequest("Username is taken");
            using var hmac = new HMACSHA512();
            var user = new AppUser{
                UserName = register.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(register.Password)),
                PasswordSalt = hmac.Key
            };
            _contxt.Users.Add(user);
            await _contxt.SaveChangesAsync();

            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login (LoginDTO login){

            var user = await _contxt.Users.SingleOrDefaultAsync(x => x.UserName.ToLower() == login.UserName.ToLower());
            if(user == null) return Unauthorized("Username is invalid");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(login.Password));

            for (int i = 0; i < computedHash.Length; i++){
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized ("Password is invalid");
            }
            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExist (string username){

            return await _contxt.Users.AnyAsync(user => user.UserName == username.ToLower());

        }
        
    }
}
