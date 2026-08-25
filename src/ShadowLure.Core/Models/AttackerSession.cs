using System;
using System.Collections.Generic;

namespace ShadowLure.Core.Models
{
    public class AttackerSession
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid WorkspaceId { get; set; }
        public Workspace? Workspace { get; set; }
        public string Fingerprint { get; set; } = string.Empty;
        public string AttackerIp { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;

        public int RiskScore { get; set; } = 0;
        public string RiskLevel { get; set; } = "Low"; // Low, Medium, High, Critical

        public int MaxChainDepth { get; set; } = 1;
        public bool AutomationDetected { get; set; } = false;
        public int DataExfilAttempts { get; set; } = 0;

        public string LlmProfileSummary { get; set; } = "Session initialized. Monitoring behavioral signals...";

        public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
        public DateTime LastSeen { get; set; } = DateTime.UtcNow;

        public List<TriggerEvent> Events { get; set; } = new();
    }
}
