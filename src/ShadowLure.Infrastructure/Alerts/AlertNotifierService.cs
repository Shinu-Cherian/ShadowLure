using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using ShadowLure.Core.Models;

namespace ShadowLure.Infrastructure.Alerts
{
    public interface IAlertNotifier
    {
        Task SendTriggerAlertAsync(TriggerEvent triggerEvent, CanaryToken token, AttackerSession session, string webhookUrl);
    }

    public class AlertNotifierService : IAlertNotifier
    {
        private readonly HttpClient _httpClient;

        // Shared across every request-scoped instance of this service (static, like
        // MetricsService) so the limit applies process-wide. A high-velocity automated
        // scanner hitting many canaries in a burst must not be able to flood the
        // operator's Slack/webhook channel with one message per trigger; see
        // ARCHITECTURE.md "Known Limitations" #3.
        private static readonly RateLimiter WebhookRateLimiter = new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            TokenLimit = 5,
            TokensPerPeriod = 1,
            ReplenishmentPeriod = TimeSpan.FromSeconds(2),
            QueueLimit = 0,
            AutoReplenishment = true
        });

        public AlertNotifierService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task SendTriggerAlertAsync(TriggerEvent triggerEvent, CanaryToken token, AttackerSession session, string webhookUrl)
        {
            if (string.IsNullOrWhiteSpace(webhookUrl)) return;

            using var lease = WebhookRateLimiter.AttemptAcquire(1);
            if (!lease.IsAcquired)
            {
                // Dropped by design: the leaky bucket is full because this attacker
                // session is triggering canaries faster than an operator could read
                // alerts anyway. The trigger event itself is still persisted and
                // visible on the dashboard/SSE feed; only the outbound webhook is skipped.
                return;
            }

            try
            {
                var payload = new
                {
                    text = $"🚨 *SHADOWLURE INTRUSION ALERT* 🚨\n" +
                           $"*Target Decoy:* {EscapeSlackText(token.Name)} ({token.Type})\n" +
                           $"*Attacker IP:* `{EscapeSlackText(triggerEvent.AttackerIp)}`\n" +
                           $"*Tool Signature:* {EscapeSlackText(triggerEvent.SimulatedTool)}\n" +
                           $"*Chain Depth:* Level {triggerEvent.ChainDepth}\n" +
                           $"*Risk Level:* *{session.RiskLevel.ToUpperInvariant()}* ({session.RiskScore}/100)\n" +
                           $"*Command Executed:* `{EscapeSlackText(triggerEvent.RequestPayload)}`"
                };

                using var request = new HttpRequestMessage(HttpMethod.Post, webhookUrl);
                request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                await _httpClient.SendAsync(request);
            }
            catch
            {
                // Best-effort delivery: a slow or unreachable webhook must never take
                // down capture of the underlying trigger event.
            }
        }

        // Slack mrkdwn treats &, <, > as control characters (used for entity
        // references and link syntax). Every field above is attacker-controlled
        // (canary name, request payload, tool signature), so it must be escaped
        // before being embedded in the message text — otherwise a crafted payload
        // like "<!channel>" or "<https://evil.example|click>" renders as a link or
        // an @here/@channel ping inside the operator's own Slack workspace.
        private static string EscapeSlackText(string? value)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            return value
                .Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;");
        }
    }
}
