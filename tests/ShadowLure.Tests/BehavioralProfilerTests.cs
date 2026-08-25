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
    }
}
