using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

    public class AccountController : BaseApiController
    {

        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IMapper _mapper;
        private readonly ITokenService _tokenService;
        private readonly DataContext _db;
        public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, ITokenService tokenService, IMapper mapper, DataContext db)
        {
            _db = db;
            _mapper = mapper;
            _signInManager = signInManager;
            _userManager = userManager;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            var username = registerDto.FirstName.ToLower() + '.' + registerDto.LastName.ToLower();
            if (await UserExists(username)) return BadRequest("User exists.");

            var user = _mapper.Map<AppUser>(registerDto);
            user.UserName = username;
            user.Email = registerDto.Email;

            var result = await _userManager.CreateAsync(user, registerDto.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            var roleResult = await _userManager.AddToRoleAsync(user, "Client");
            if (!roleResult.Succeeded) return BadRequest(result.Errors);

            var client = new Client
            {
                AppUser = user,
                EmailNotification = true,
                SmsNotification = true
            };

            await _db.Client.AddAsync(client);
            await _db.SaveChangesAsync();

            return new UserDto
            {
                ClientId = client.Id,
                Username = user.UserName,
                Token = await _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _userManager.Users.Include(x => x.Photo).SingleOrDefaultAsync(x => x.Email == loginDto.Email);

            if (user == null) return Unauthorized("User not found.");

            var result = await _signInManager
                .CheckPasswordSignInAsync(user, loginDto.Password, false);

            if (!result.Succeeded) return Unauthorized();
            //privremeno rjesenje
            int? clientId = null;
            int? barberId = null;
            if (await _userManager.IsInRoleAsync(user, "Client"))
            {
                clientId = _db.Client.Where(x => x.AppUserId == user.Id).Select(x => x.Id).Single();
            }
            else if (await _userManager.IsInRoleAsync(user, "Barber"))
            {
                barberId = _db.Barber.Where(x => x.AppUserId == user.Id).Select(x => x.Id).Single();
            }
            return new UserDto
            {
                ClientId = clientId,
                BarberId = barberId,
                Username = user.UserName,
                Token = await _tokenService.CreateToken(user),
                Photo = _mapper.Map<PhotoDto>(user.Photo)
            };
        }

        private async Task<bool> UserExists(string username)
        {
            return await _userManager.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}