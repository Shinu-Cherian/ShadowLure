using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
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

        public AlertNotifierService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task SendTriggerAlertAsync(TriggerEvent triggerEvent, CanaryToken token, AttackerSession session, string webhookUrl)
        {
            if (string.IsNullOrWhiteSpace(webhookUrl)) return;

            try
            {
                var payload = new
                {
                    text = $"🚨 *SHADOWLURE INTRUSION ALERT* 🚨\n" +
                           $"*Target Decoy:* {token.Name} ({token.Type})\n" +
                           $"*Attacker IP:* `{triggerEvent.AttackerIp}`\n" +
                           $"*Tool Signature:* {triggerEvent.SimulatedTool}\n" +
                           $"*Chain Depth:* Level {triggerEvent.ChainDepth}\n" +
                           $"*Risk Level:* *{session.RiskLevel.ToUpper()}* ({session.RiskScore}/100)\n" +
                           $"*Command Executed:* `{triggerEvent.RequestPayload}`"
                };

                using var request = new HttpRequestMessage(HttpMethod.Post, webhookUrl);
                request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                await _httpClient.SendAsync(request);
            }
            catch
            {
                // Silently log or retry on alert delivery failure
            }
        }
    }
}
