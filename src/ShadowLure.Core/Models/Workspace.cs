using System;
using System.Collections.Generic;

namespace ShadowLure.Core.Models
{
    public class Workspace
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Name { get; set; } = "Acme Security Operations";
        public string ApiKey { get; set; } = $"sl_live_{Guid.NewGuid():N}";
        public string SlackWebhookUrl { get; set; } = string.Empty;
        public string GenericWebhookUrl { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public List<CanaryToken> CanaryTokens { get; set; } = new();
        public List<AttackerSession> AttackerSessions { get; set; } = new();
    }
}
