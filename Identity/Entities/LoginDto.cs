using System.ComponentModel.DataAnnotations;

namespace Identity.Entities
{
    public class LoginDto
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
