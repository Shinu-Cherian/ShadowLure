using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ShadowLure.Core.Models;

namespace ShadowLure.Profiling
{
    public interface IBehavioralProfiler
    {
        string GenerateFingerprint(string ip, string userAgent);
        (int RiskScore, string RiskLevel) CalculateRisk(AttackerSession session);
        string DetectToolSignature(string userAgent, string path);
        bool IsAutomationTool(string userAgent, List<TriggerEvent> events);
    }

    public class BehavioralProfiler : IBehavioralProfiler
    {
        public string GenerateFingerprint(string ip, string userAgent)
        {
            var raw = $"{ip}|{userAgent}";
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
            return Convert.ToHexString(bytes)[..12].ToLower();
        }

        public string DetectToolSignature(string userAgent, string path)
        {
            var ua = userAgent.ToLower();
            if (ua.Contains("aws-cli")) return "AWS CLI v2";
            if (ua.Contains("boto3")) return "Python Boto3 SDK";
            if (ua.Contains("python-requests") || ua.Contains("python")) return "Python Script / Automation";
            if (ua.Contains("go-http-client")) return "Go Security Scanner";
            if (ua.Contains("psql")) return "PostgreSQL Client (psql)";
            if (ua.Contains("kubectl")) return "Kubernetes CLI (kubectl)";
            if (ua.Contains("curl")) return "cURL CLI Tool";
            if (ua.Contains("nmap")) return "Nmap Scanner";
            if (ua.Contains("metasploit")) return "Metasploit Framework";

            return "Browser / HTTP Client";
        }

        public bool IsAutomationTool(string userAgent, List<TriggerEvent> events)
        {
            var ua = userAgent.ToLower();
            if (ua.Contains("aws-cli") || ua.Contains("boto3") || ua.Contains("python") || ua.Contains("curl") || ua.Contains("go-http"))
            {
                return true;
            }

            if (ua.Contains("kubectl"))
            {
                return true;
            }

            if (events.Count >= 2)
            {
                var sorted = events.OrderBy(e => e.TriggeredAt).ToList();
                var intervals = new List<double>();
                for (int i = 1; i < sorted.Count; i++)
                {
                    intervals.Add((sorted[i].TriggeredAt - sorted[i - 1].TriggeredAt).TotalSeconds);
                }

                if (intervals.Count > 0 && intervals.Average() < 2.0)
                {
                    return true;
                }
            }

            return false;
        }

        public (int RiskScore, string RiskLevel) CalculateRisk(AttackerSession session)
        {
            int triggerCount = session.Events.Count;
            int chainDepth = session.MaxChainDepth;
            bool automation = session.AutomationDetected;
            int exfilAttempts = session.DataExfilAttempts;

            // Risk Score Formula from Pitch:
            // Risk = (trigger_count * 10) + (chain_depth * 25) + (automation * 15) + (exfil * 50)
            int score = (triggerCount * 10) + (chainDepth * 25) + (automation ? 15 : 0) + (exfilAttempts * 50);

            string level = score switch
            {
                >= 100 => "Critical",
                >= 60 => "High",
                >= 30 => "Medium",
                _ => "Low"
            };

            // Documented everywhere (README, ARCHITECTURE.md, the dashboard's risk
            // ring) as a 0-100 scale. A session with several chained triggers and an
            // exfil attempt easily exceeds 100 (e.g. 3 events + depth 2 + automation +
            // 1 exfil = 145), so the score must be capped for display even though the
            // level thresholds above already saturate at "Critical" past 100.
            return (Math.Min(score, 100), level);
        }
    }
}
