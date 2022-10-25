using System;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/barbers")]
    public class BarberController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly IMapper _mapper;
        private readonly UserManager<AppUser> _userManager;
        private readonly IPhotoService _photoService;

        public BarberController(DataContext context, IMapper mapper, UserManager<AppUser> userManager, IPhotoService photoService)
        {
            _photoService = photoService;
            _userManager = userManager;
            _context = context;
            _mapper = mapper;
        }

        [HttpGet]
        public async Task<ActionResult<BarberDto[]>> GetBarberAsync()
        {
            var barbers = await _context.Barber.Include(x => x.AppUser).ThenInclude(x => x.Photo).ToListAsync();
            return _mapper.Map<BarberDto[]>(barbers);
        }

        [HttpGet("{id}", Name = "GetBarber")]
        public async Task<ActionResult<BarberDto>> GetBarberAsync(int id)
        {
            var barber = await _context.Barber.Include(x => x.AppUser).ThenInclude(x => x.Photo).Include(x => x.BarberServices).ThenInclude(x => x.Service).SingleOrDefaultAsync(x => x.Id == id);
            if (barber == null)
            {
                return NotFound();
            }
            return _mapper.Map<BarberDto>(barber);
        }

        [Authorize("RequireBarberRole")]
        [HttpGet("username/{username}")]
        public async Task<ActionResult<BarberDto>> GetBarberByUsernameAsync(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return NotFound();

            var barber = await _context.Barber.Include(x => x.AppUser).ThenInclude(x => x.Photo).Include(x => x.BarberServices).ThenInclude(x => x.Service).SingleOrDefaultAsync(x => x.AppUserId == user.Id);
            if (barber == null) return NotFound();

            return _mapper.Map<BarberDto>(barber);
        }

        [Authorize("RequireAdminRole")]
        [HttpPost]
        public async Task<ActionResult<bool>> PostBarberAsync(BarberDto model)
        {
            var username = model.FirstName.ToLower() + "." + model.LastName.ToLower();
            if (await UserExists(username))
                return BadRequest("Username already taken");

            var newUser = new AppUser
            {
                UserName = username,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
                DateOfBirth = model.DateOfBirth,
                FirstName = model.FirstName,
                LastName = model.LastName
            };
            await _userManager.CreateAsync(newUser, "Barber0!");
            await _userManager.AddToRoleAsync(newUser, "Barber");

            var user = await _userManager.FindByNameAsync(newUser.UserName);
            var barber = new Barber
            {
                AppUser = user,
                Info = model.Info
            };

            _context.Add(barber);
            await _context.SaveChangesAsync();

            return Ok();
        }

        [Authorize("RequireBarberOrAdminRole")]
        [HttpPut("{id}")]
        public async Task<ActionResult<BarberDto>> PutBarberAsync(int id, BarberDto model)
        {
            var barber = await _context.Barber.Include(x => x.AppUser).Include(x => x.BarberServices).SingleOrDefaultAsync(x => x.Id == id);

            if (barber == null)
            {
                return BadRequest();
            }
            var entity = _mapper.Map(model, barber);
            var user = barber.AppUser;

            _context.Update(entity);
            await _userManager.UpdateAsync(user);
            await _context.SaveChangesAsync();

            return Ok(model);
        }

        [Authorize("RequireAdminRole")]
        [HttpDelete("{id}")]
        public async Task<ActionResult<bool>> DeleteAsync(int id)
        {
            var barber = await _context.Barber.SingleOrDefaultAsync(x => x.Id == id);

            if (barber == null)
            {
                return NotFound();
            }
            var user = await _userManager.FindByIdAsync(barber.AppUserId.ToString());

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest();
            }
            return true;
        }

        [HttpPost("{barberId}/add-photo")]
        [Authorize("RequireBarberOrAdminRole")]
        public async Task<ActionResult<PhotoDto>> UploadPhotoAsync(int barberId, IFormFile file)
        {
            var barber = await _context.Barber.Include(x => x.AppUser).SingleOrDefaultAsync(x => x.Id == barberId);

            var result = await _photoService.AddPhotoAsync(file);
            if (result.Error != null) return BadRequest(result.Error.Message);

            var photo = new Photo
            {
                Url = result.SecureUrl.AbsoluteUri,
                PublicId = result.PublicId
            };

            barber.AppUser.Photo = photo;

            _context.Update(barber);
            await _context.SaveChangesAsync();

            return CreatedAtRoute("GetBarber", new { id = barber.Id }, _mapper.Map<PhotoDto>(photo));
        }

        private async Task<bool> UserExists(string username)
        {
            return await _userManager.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}