using ShadowLure.Shadow.Services;
using Xunit;

namespace ShadowLure.Tests
{
    public class ShadowEngineTests
    {
        private readonly ShadowEngine _engine = new();

        [Fact]
        public void GenerateS3BucketListing_ContainsBucketNameAndBreadcrumb()
        {
            var tokenName = "prod-s3-key";
            var breadcrumb = "postgresql://ledger_ro@prod-db.internal:5432/customers";

            var result = _engine.GenerateS3BucketListing(tokenName, breadcrumb);

            Assert.Contains("acme-prod-backups-2026", result);
            Assert.Contains(breadcrumb, result);
        }

        [Fact]
        public void GenerateFakeCsvData_ContainsHeadersAndBreadcrumb()
        {
            var tableName = "customer_ledgers";
            var fileName = "export.csv";
            var breadcrumb = "k8s://payments/prod/eks-secret";

            var csv = _engine.GenerateFakeCsvData(tableName, fileName, breadcrumb);

            Assert.Contains("id,first_name,last_name,email,ssn,account_balance", csv);
            Assert.Contains(breadcrumb, csv);
            Assert.Contains("Alex", csv);
        }
    }
}
