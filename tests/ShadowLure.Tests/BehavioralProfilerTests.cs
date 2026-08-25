using ShadowLure.Core.Models;
using ShadowLure.Profiling;
using Xunit;

namespace ShadowLure.Tests
{
    public class BehavioralProfilerTests
    {
        private readonly BehavioralProfiler _profiler = new();

        [Fact]
        public void GenerateFingerprint_ProducesDeterministicSha256Hash()
        {
            var ip = "192.168.1.100";
            var userAgent = "aws-cli/2.15.10 Python/3.11.6";

            var hash1 = _profiler.GenerateFingerprint(ip, userAgent);
            var hash2 = _profiler.GenerateFingerprint(ip, userAgent);

            Assert.Equal(12, hash1.Length);
            Assert.Equal(hash1, hash2);
        }

        [Theory]
        [InlineData("aws-cli/2.15.10", true)]
        [InlineData("kubectl/v1.30 (linux/amd64)", true)]
        [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false)]
        public void IsAutomationTool_DetectsCliSignatures(string userAgent, bool expectedAutomation)
        {
            var events = new List<TriggerEvent>();
            var isAutomation = _profiler.IsAutomationTool(userAgent, events);

            Assert.Equal(expectedAutomation, isAutomation);
        }

        [Fact]
        public void DetectToolSignature_ClassifiesUserAgentsCorrectly()
        {
            Assert.Equal("AWS CLI v2", _profiler.DetectToolSignature("aws-cli/2.15.10", "/api/shadow/aws/123"));
            Assert.Equal("PostgreSQL Client (psql)", _profiler.DetectToolSignature("psql/16.1", "/api/shadow/db/123"));
            Assert.Equal("Kubernetes CLI (kubectl)", _profiler.DetectToolSignature("kubectl/v1.30", "/api/shadow/k8s/123"));
        }

        // CalculateRisk implements the formula documented in ARCHITECTURE.md:
        //   Risk = (events * 10) + (maxChainDepth * 25) + (automation * 15) + (exfilAttempts * 50), capped at 100.
        // It previously had no test coverage at all, and Program.cs used to
        // reimplement the same formula inline instead of calling it - the two
        // copies could silently drift apart. These tests pin the single
        // source-of-truth behavior now that Program.cs calls this method directly.
        [Theory]
        [InlineData(0, 0, false, 0, 0, "Low")]
        [InlineData(1, 1, false, 0, 35, "Medium")]
        [InlineData(2, 1, true, 0, 60, "High")]
        [InlineData(1, 1, false, 1, 85, "High")]
        [InlineData(3, 2, true, 1, 145, "Critical")]
        public void CalculateRisk_MatchesDocumentedFormula(int eventCount, int maxChainDepth, bool automation, int exfilAttempts, int expectedRawScore, string expectedLevel)
        {
            var session = new AttackerSession
            {
                MaxChainDepth = maxChainDepth,
                AutomationDetected = automation,
                DataExfilAttempts = exfilAttempts,
                Events = Enumerable.Range(0, eventCount).Select(_ => new TriggerEvent()).ToList()
            };

            var (score, level) = _profiler.CalculateRisk(session);

            Assert.Equal(Math.Min(expectedRawScore, 100), score);
            Assert.Equal(expectedLevel, level);
        }

        [Fact]
        public void CalculateRisk_NeverExceedsOneHundred()
        {
            var session = new AttackerSession
            {
                MaxChainDepth = 10,
                AutomationDetected = true,
                DataExfilAttempts = 5,
                Events = Enumerable.Range(0, 20).Select(_ => new TriggerEvent()).ToList()
            };

            var (score, level) = _profiler.CalculateRisk(session);

            Assert.Equal(100, score);
            Assert.Equal("Critical", level);
        }
    }
}
