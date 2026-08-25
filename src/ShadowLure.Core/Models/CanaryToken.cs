using System;
using System.Collections.Generic;

namespace ShadowLure.Core.Models
{
    public enum TokenType
    {
        AwsKey,
        DbConnection,
        ApiKey,
        K8sSecret
    }

    public enum TokenStatus
    {
        Active,
        Triggered,
        Expired
    }

    public class CanaryToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid WorkspaceId { get; set; }
        public Workspace? Workspace { get; set; }
        public string Name { get; set; } = string.Empty;
        public TokenType Type { get; set; }
        public string DecoyValue { get; set; } = string.Empty;
        public string TargetService { get; set; } = string.Empty;
        public TokenStatus Status { get; set; } = TokenStatus.Active;
        public int TriggerCount { get; set; } = 0;
        public string ContextInfo { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Breadcrumbs / Deception Chain relationships
        public List<CanaryLink> OutgoingLinks { get; set; } = new();
        public List<CanaryLink> IncomingLinks { get; set; } = new();
        public List<TriggerEvent> TriggerEvents { get; set; } = new();
    }

    public class CanaryLink
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid SourceCanaryId { get; set; }
        public CanaryToken? SourceCanary { get; set; }

        public Guid TargetCanaryId { get; set; }
        public CanaryToken? TargetCanary { get; set; }

        public string Description { get; set; } = string.Empty; // e.g., "Leaked connection string inside S3 bucket"
        public string BreadcrumbLocation { get; set; } = string.Empty; // e.g., "s3://prod-customer-data-eu/db-creds.env"
        public DateTime LinkedAt { get; set; } = DateTime.UtcNow;
    }
}
