using Identity.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.Controllers
{
    [Route("api/events")]
    [ApiController]
    [Authorize]
    public class EventController : Controller
    {
        private readonly UserManager<IdentityUser<Guid>> _userManager;
        private readonly IdentityContext _context;


        public EventController(
            UserManager<IdentityUser<Guid>> userManager, IdentityContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        [HttpGet]
        [HttpGet("{eventId}", Name = "GetEventById")]
        public async Task<IActionResult> GetEventById(int eventId)
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);

            Event e = await _context.Events
                .FirstOrDefaultAsync(e => e.EventId == eventId);
            if (e == null)
            {
                return NotFound();
            }

            return Ok(e);
        }

        [HttpPost("{eventId}/createuser")]
        [TypeFilter(typeof(RoleValidator), Arguments = new object[] { new string[] { Roles.ADMIN } })]
        public async Task<IActionResult> CreateUser(int eventId, Teammember teammember)
        {
            if (teammember == null)
            {
                return BadRequest();
            }

            if (teammember.Emailaddress == null || teammember.Role == null)
            {
                ModelState.AddModelError("RequiredFields", "Not all required fields are filled in.");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await CreateUser(teammember);
            IdentityUser<Guid> eventUser = null;

            if (result.Succeeded)
            {
                eventUser = await _userManager.FindByEmailAsync(teammember.Emailaddress);
                await AddEventToUser(eventId, eventUser.Id, teammember.Role);
                return Ok();
            }
            else
            {
                return StatusCode(500);
            }
        }

        private async Task AddEventToUser(int eventId, Guid userId, string userRole)
        {
            var role = _context.Roles.FirstOrDefault(r => r.Name == userRole);

            if (role != null)
            {
                AppUserRoleEvent appUserRoleEvent = new AppUserRoleEvent
                {
                    EventId = eventId,
                    UserId = userId,
                    RoleId = role.Id
                };

                await _context.UserRoles.AddAsync(appUserRoleEvent);
                await _context.SaveChangesAsync();
            }
        }

        private async Task<IdentityResult> CreateUser(Teammember teammember)
        {
            string password = "SuperSecretPassword";
            var user = new IdentityUser<Guid>
            {
                UserName = teammember.Emailaddress,
                Email = teammember.Emailaddress
            };
            var result = await _userManager.CreateAsync(user, password);
            return result;
        }
    }
}