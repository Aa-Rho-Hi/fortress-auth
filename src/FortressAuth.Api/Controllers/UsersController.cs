
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FortressAuth.Api.Data;

namespace FortressAuth.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController(AppDbContext db) : ControllerBase
{
    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var sub = User.Claims.FirstOrDefault(c => c.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
        if (sub is null) return Unauthorized();
        var id = Guid.Parse(sub);
        var user = await db.Users.FindAsync(id);
        if (user is null) return NotFound();
        return Ok(new { user.Id, user.Email, user.Role, user.MfaEnabled });
    }
}
