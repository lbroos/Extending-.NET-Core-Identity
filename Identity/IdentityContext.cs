using Identity.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace Identity
{
    public class IdentityContext : IdentityDbContext<IdentityUser<Guid>, IdentityRole<Guid>, Guid, IdentityUserClaim<Guid>, AppUserRoleEvent, IdentityUserLogin<Guid>, IdentityRoleClaim<Guid>, IdentityUserToken<Guid>>
    {
        public IdentityContext()
        {
        }

        public IdentityContext(DbContextOptions<IdentityContext> options) : base(options)
        {
        }

        public virtual DbSet<Event> Events { get; set; }
        public virtual DbSet<AppUserRoleEvent> AppUserRoleEvents { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<AppUserRoleEvent>()
                .HasKey(k => new { k.RoleId, k.UserId, k.EventId });

            modelBuilder.Entity<AppUserRoleEvent>()
                .Property(p => p.EventId)
                .HasDefaultValue(0);
        }
    }
}
