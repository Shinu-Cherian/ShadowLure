using System;
using System.Collections.Generic;

namespace ShadowLure.Shadow.Services
{
    public interface IShadowEngine
    {
        string GenerateS3BucketListing(string tokenName, string? breadcrumbLink = null);
        string GenerateFakeCsvData(string bucketName, string fileName, string? breadcrumbLink = null);
        string GenerateDbQueryResponse(string query, string? breadcrumbLink = null);
    }

    public class ShadowEngine : IShadowEngine
    {
        public string GenerateS3BucketListing(string tokenName, string? breadcrumbLink = null)
        {
            var dateStr = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            var companyPrefix = tokenName.ToLower().Replace(" ", "-");
            if (companyPrefix.Contains("-key") || companyPrefix.Contains("-aws"))
            {
                companyPrefix = "acme";
            }

            return $"""
            {dateStr}   {companyPrefix}-prod-backups-2026
            {dateStr}   {companyPrefix}-customer-data-eu
            {dateStr}   {companyPrefix}-finance-reports-q3
            {dateStr}   {companyPrefix}-internal-dev-keys
            {dateStr}   {(string.IsNullOrEmpty(breadcrumbLink) ? $"{companyPrefix}-db-sync.env" : breadcrumbLink)}
            """;
        }

        public string GenerateFakeCsvData(string bucketName, string fileName, string? breadcrumbLink = null)
        {
            var breadcrumbComment = string.IsNullOrEmpty(breadcrumbLink) 
                ? "# CONFIDENTIAL ACME CORP INTERNAL DATA" 
                : $"# NOTE: DB SYNC ACTIVE AT {breadcrumbLink}";

            return $"""
            {breadcrumbComment}
            id,first_name,last_name,email,ssn,account_balance
            1,Alex,Mercer,alex.mercer@acmecorp.internal,458-12-9843,$142,500.00
            2,Sarah,Connor,sarah.c@cyberdyne.corp,891-45-1102,$89,210.50
            3,Marcus,Vance,vance.m@acmecorp.internal,230-99-4781,$1,250,000.00
            4,Elena,Rostova,elena.r@acmecorp.internal,712-34-9012,$45,000.00
            5,David,Kim,david.kim@acmecorp.internal,549-88-3190,$612,400.00
            """;
        }

        public string GenerateDbQueryResponse(string query, string? breadcrumbLink = null)
        {
            var upperQuery = query.ToUpper();
            if (upperQuery.Contains("KUBECTL") || upperQuery.Contains("SECRETS"))
            {
                return $"""
                apiVersion: v1
                kind: Secret
                metadata:
                  name: payments-prod-service-account
                  namespace: payments
                  annotations:
                    shadowlure.io/next-breadcrumb: {(string.IsNullOrEmpty(breadcrumbLink) ? "https://billing.internal/v1/invoices" : breadcrumbLink)}
                type: Opaque
                data:
                  token: c2hsX2FwaV9saXZlX2VmM2MyYmIxYjk1MjRiOGY5YTFm
                """;
            }

            if (upperQuery.Contains("INTERNAL") || upperQuery.Contains("INVOICES"))
            {
                return """
                {
                  "status": "ok",
                  "tenant": "enterprise",
                  "records": [
                    { "invoice_id": "INV-2026-1048", "amount": 84210.55, "contact": "finance-controller@acme.internal" },
                    { "invoice_id": "INV-2026-1092", "amount": 132900.00, "contact": "security-procurement@acme.internal" }
                  ],
                  "deception_note": "shadow response served; attacker path contained"
                }
                """;
            }

            if (upperQuery.Contains("SELECT") && upperQuery.Contains("USERS"))
            {
                return """
                [
                  {"id": 101, "username": "admin_root", "role": "SuperAdmin", "last_login": "2026-08-25T10:14:02Z"},
                  {"id": 102, "username": "dev_service_acct", "role": "Developer", "last_login": "2026-08-24T18:22:11Z"}
                ]
                """;
            }

            return $"""
            Query executed successfully. 2 rows returned.
            Breadcrumb Active: {(string.IsNullOrEmpty(breadcrumbLink) ? "None" : breadcrumbLink)}
            """;
        }
    }
}
