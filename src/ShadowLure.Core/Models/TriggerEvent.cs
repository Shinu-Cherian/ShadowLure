using System;

namespace ShadowLure.Core.Models
{
    public class TriggerEvent
    {
        public Guid Id { get; set; } = Guid.NewGuid();

        public Guid CanaryTokenId { get; set; }
        public CanaryToken? CanaryToken { get; set; }

        public Guid? AttackerSessionId { get; set; }
        public AttackerSession? AttackerSession { get; set; }

        public string AttackerIp { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public string RequestMethod { get; set; } = "GET";
        public string RequestPath { get; set; } = string.Empty;
        public string RequestPayload { get; set; } = string.Empty;
        public string ResponsePayload { get; set; } = string.Empty;

        public int ChainDepth { get; set; } = 1;
        public string SimulatedTool { get; set; } = "Unknown";
        public bool IsAutomationScript { get; set; } = false;

        public DateTime TriggeredAt { get; set; } = DateTime.UtcNow;
    }
}
