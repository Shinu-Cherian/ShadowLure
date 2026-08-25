using Microsoft.EntityFrameworkCore;
using ShadowLure.Core.Models;

namespace ShadowLure.Infrastructure.Data
{
    public class ShadowLureDbContext : DbContext
    {
        public ShadowLureDbContext(DbContextOptions<ShadowLureDbContext> options) : base(options) { }

        public DbSet<Workspace> Workspaces => Set<Workspace>();
        public DbSet<CanaryToken> CanaryTokens => Set<CanaryToken>();
        public DbSet<CanaryLink> CanaryLinks => Set<CanaryLink>();
        public DbSet<TriggerEvent> TriggerEvents => Set<TriggerEvent>();
        public DbSet<AttackerSession> AttackerSessions => Set<AttackerSession>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<CanaryToken>()
                .HasOne(c => c.Workspace)
                .WithMany(w => w.CanaryTokens)
                .HasForeignKey(c => c.WorkspaceId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<AttackerSession>()
                .HasOne(s => s.Workspace)
                .WithMany(w => w.AttackerSessions)
                .HasForeignKey(s => s.WorkspaceId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<CanaryLink>()
                .HasOne(l => l.SourceCanary)
                .WithMany(c => c.OutgoingLinks)
                .HasForeignKey(l => l.SourceCanaryId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<CanaryLink>()
                .HasOne(l => l.TargetCanary)
                .WithMany(c => c.IncomingLinks)
                .HasForeignKey(l => l.TargetCanaryId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<TriggerEvent>()
                .HasOne(e => e.CanaryToken)
                .WithMany(c => c.TriggerEvents)
                .HasForeignKey(e => e.CanaryTokenId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<TriggerEvent>()
                .HasOne(e => e.AttackerSession)
                .WithMany(s => s.Events)
                .HasForeignKey(e => e.AttackerSessionId)
                .OnDelete(DeleteBehavior.SetNull);
        }
    }
}
