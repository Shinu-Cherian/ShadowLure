using Prometheus;

namespace ShadowLure.Infrastructure.Observability
{
    public static class MetricsService
    {
        public static readonly Counter CanaryTriggersTotal = Metrics
            .CreateCounter("shadowlure_canary_triggers_total", "Total count of canary trigger events captured.", new CounterConfiguration
            {
                LabelNames = new[] { "token_type", "simulated_tool", "risk_level" }
            });

        public static readonly Counter DataExfiltrationAttemptsTotal = Metrics
            .CreateCounter("shadowlure_data_exfiltration_attempts_total", "Total count of fake data exfiltration file downloads.");

        public static readonly Gauge ActiveAttackerSessions = Metrics
            .CreateGauge("shadowlure_active_attacker_sessions", "Number of currently active attacker sessions monitored.");

        public static readonly Histogram ChainDepthDistribution = Metrics
            .CreateHistogram("shadowlure_chain_depth_distribution", "Distribution of attack chain depths reached by attackers.", new HistogramConfiguration
            {
                Buckets = Histogram.LinearBuckets(start: 1, width: 1, count: 5)
            });
    }
}
