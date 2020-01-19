using Microsoft.AspNetCore.Identity;
using System;

namespace Identity.Entities
{
    public class AppUserRoleEvent : IdentityUserRole<Guid>
    {
        public int EventId { get; set; }
    }
}
