using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Prometheus;
using Serilog;
using ShadowLure.Core.Models;
using ShadowLure.Infrastructure.Alerts;
using ShadowLure.Infrastructure.Data;
using ShadowLure.Infrastructure.LLM;
using ShadowLure.Infrastructure.Observability;
using ShadowLure.Profiling;
using ShadowLure.Shadow.Services;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();
builder.Host.UseSerilog();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Data Source=shadowlure.db";

builder.Services.AddDbContext<ShadowLureDbContext>(options =>
{
    if (connectionString.Contains("Host=", StringComparison.OrdinalIgnoreCase))
    {
        options.UseNpgsql(connectionString);
    }
    else
    {
        options.UseSqlite(connectionString);
    }
});

builder.Services.AddScoped<IShadowEngine, ShadowEngine>();
builder.Services.AddScoped<IBehavioralProfiler, BehavioralProfiler>();

// Typed clients so the Groq LLM call and the Slack/webhook call each get their
// own bounded timeout. Both run off the hot path of a shadow-trap response (see
// QueueShadowCapture below), but a background task with no timeout can still pile
// up indefinitely against a hung upstream, so we bound it anyway.
builder.Services.AddHttpClient<ILlmService, GroqLlmService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(10);
});
builder.Services.AddHttpClient<IAlertNotifier, AlertNotifierService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(5);
});

// Authenticates operator-only actions (deploy/revoke canary, reset workspace,
// run simulations). Shadow trap endpoints under /api/shadow/* are deliberately
// left open - attackers must be able to hit them without credentials - but the
// management API was previously wide open too, including POST /api/reset, which
// is documented in this very README and would let an attacker who fingerprinted
// ShadowLure wipe their own forensic trail with one unauthenticated request.
var operatorApiKey = builder.Configuration["OPERATOR_API_KEY"];
if (string.IsNullOrWhiteSpace(operatorApiKey))
{
    if (builder.Environment.IsProduction())
    {
        throw new InvalidOperationException(
            "OPERATOR_API_KEY must be set in Production. It authenticates canary management " +
            "requests (deploy/revoke/reset/simulate) so the admin API cannot be driven by an " +
            "unauthenticated third party. Generate one with: openssl rand -hex 32");
    }

    operatorApiKey = "dev-local-operator-key";
}

var app = builder.Build();

if (string.Equals(operatorApiKey, "dev-local-operator-key", StringComparison.Ordinal))
{
    Log.Warning("OPERATOR_API_KEY not set - using an insecure development-only default. Set it before deploying.");
    // The dashboard and every other read endpoint now require this key too (not
    // just mutations), so a bare http://localhost:5246 will 401. Since a fresh
    // clone has no other way to discover the key, print the exact URL to open.
    var httpUrl = app.Urls.FirstOrDefault() ?? "http://localhost:5246";
    Log.Information("Dashboard: {Url}", $"{httpUrl}/?key={operatorApiKey}");
}

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ShadowLureDbContext>();
    db.Database.EnsureCreated();
    await SeedWorkspaceAsync(db);
}

app.UseHttpMetrics();
app.MapMetrics("/metrics").AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/", async (ShadowLureDbContext db) =>
{
    var snapshot = await LoadDashboardSnapshotAsync(db);
    return Results.Content(RenderFullDashboardHtml(snapshot), "text/html");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/api/canaries/table", async (ShadowLureDbContext db) =>
{
    var snapshot = await LoadDashboardSnapshotAsync(db);
    return Results.Content(RenderCanaryTablePartial(snapshot.Canaries), "text/html");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/api/canaries/modal", () =>
{
    return Results.Content(RenderCreateCanaryModalPartial(), "text/html");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/api/canaries/{id:guid}/details", async (Guid id, ShadowLureDbContext db) =>
{
    var canary = await db.CanaryTokens
        .Include(c => c.OutgoingLinks).ThenInclude(l => l.TargetCanary)
        .Include(c => c.TriggerEvents)
        .FirstOrDefaultAsync(c => c.Id == id);

    if (canary == null)
    {
        return Results.NotFound("Canary not found.");
    }

    return Results.Content(RenderCanaryDetailsModalPartial(canary), "text/html");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapDelete("/api/canaries/{id:guid}", async (Guid id, ShadowLureDbContext db) =>
{
    var canary = await db.CanaryTokens.FindAsync(id);
    if (canary != null)
    {
        var links = await db.CanaryLinks
            .Where(l => l.SourceCanaryId == id || l.TargetCanaryId == id)
            .ToListAsync();
        db.CanaryLinks.RemoveRange(links);

        var events = await db.TriggerEvents.Where(e => e.CanaryTokenId == id).ToListAsync();
        db.TriggerEvents.RemoveRange(events);

        db.CanaryTokens.Remove(canary);
        await db.SaveChangesAsync();
    }

    var snapshot = await LoadDashboardSnapshotAsync(db);
    return Results.Content(RenderCanaryTablePartial(snapshot.Canaries), "text/html");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapPost("/api/canaries", async (HttpContext context, ShadowLureDbContext db, ILlmService llm) =>
{
    var workspace = await db.Workspaces.OrderBy(w => w.CreatedAt).FirstAsync();
    var form = await context.Request.ReadFormAsync();
    var name = form["name"].ToString();
    var serviceType = form["type"].ToString();
    var techStack = form["techStack"].ToString();

    Enum.TryParse<TokenType>(serviceType, true, out var tokenType);
    var decoyValue = await llm.GenerateContextualDecoyAsync(techStack, serviceType);
    var existingCanaries = await db.CanaryTokens
        .Where(c => c.WorkspaceId == workspace.Id)
        .OrderBy(c => c.CreatedAt)
        .ToListAsync();

    var newToken = new CanaryToken
    {
        WorkspaceId = workspace.Id,
        Name = string.IsNullOrWhiteSpace(name) ? BuildCanaryName(techStack, tokenType) : name.Trim(),
        Type = tokenType,
        TargetService = HumanizeTokenType(tokenType),
        DecoyValue = decoyValue,
        Status = TokenStatus.Active,
        ContextInfo = $"Environment: {techStack}"
    };

    db.CanaryTokens.Add(newToken);

    var previous = existingCanaries.LastOrDefault();
    if (previous != null)
    {
        db.CanaryLinks.Add(new CanaryLink
        {
            SourceCanary = previous,
            TargetCanary = newToken,
            Description = "Generated breadcrumb discovered inside shadow response",
            BreadcrumbLocation = BuildBreadcrumb(newToken)
        });
    }

    await db.SaveChangesAsync();
    var snapshot = await LoadDashboardSnapshotAsync(db);
    return Results.Content(RenderCanaryTablePartial(snapshot.Canaries), "text/html");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/api/graph/data", async (ShadowLureDbContext db) =>
{
    var snapshot = await LoadDashboardSnapshotAsync(db);
    var nodes = snapshot.Canaries.Select(c => new
    {
        id = c.Id.ToString(),
        label = $"{c.Name}\n[{HumanizeTokenType(c.Type)}]",
        shape = "ellipse",
        color = new
        {
            background = c.Status == TokenStatus.Triggered ? "#3b1219" : "#0a2228",
            border = c.Status == TokenStatus.Triggered ? "#fb7185" : "#2dd4bf",
            highlight = new { background = "#13373e", border = "#5eead4" }
        },
        font = new { color = "#ffffff", face = "Inter", size = 12 },
        margin = 16,
        shadow = true,
        status = c.Status.ToString(),
        triggerCount = c.TriggerCount
    });

    var edges = snapshot.Links.Select(l => new
    {
        from = l.SourceCanaryId.ToString(),
        to = l.TargetCanaryId.ToString(),
        label = $" {l.Description} ",
        arrows = "to",
        color = new { color = "#f59e0b", highlight = "#fbbf24" },
        font = new { color = "#fbbf24", size = 11, face = "JetBrains Mono", background = "#050608", strokeWidth = 4, strokeColor = "#050608" },
        dashes = true
    });

    return Results.Json(new { nodes, edges });
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapPost("/api/shadow/aws/{tokenId:guid}", async (
    Guid tokenId,
    HttpContext context,
    ShadowLureDbContext db,
    IShadowEngine shadow,
    IServiceScopeFactory scopeFactory) =>
{
    var canary = await FindCanaryAsync(db, tokenId);
    if (canary == null)
    {
        return Results.NotFound("Invalid AWS access credential");
    }

    var bodyText = await ReadBodyAsync(context);
    var breadcrumb = canary.OutgoingLinks.FirstOrDefault()?.BreadcrumbLocation;
    var response = shadow.GenerateS3BucketListing(canary.Name, breadcrumb);
    var payload = string.IsNullOrWhiteSpace(bodyText) ? "aws s3 ls --recursive" : bodyText;
    var ip = ExtractClientIp(context);
    var userAgent = ResolveUserAgent(context, "aws-cli/2.15.10 Python/3.11.6 Linux/6.5");
    var path = context.Request.Path.ToString();

    QueueShadowCapture(scopeFactory, canary.Id, canary.Type, ip, userAgent, path, payload, response, isExfiltration: false);
    return Results.Content(response, "text/plain");
});

app.MapPost("/api/shadow/db/{tokenId:guid}", async (
    Guid tokenId,
    HttpContext context,
    ShadowLureDbContext db,
    IShadowEngine shadow,
    IServiceScopeFactory scopeFactory) =>
{
    var canary = await FindCanaryAsync(db, tokenId);
    if (canary == null)
    {
        return Results.NotFound("Database access denied");
    }

    var bodyText = await ReadBodyAsync(context);
    var breadcrumb = canary.OutgoingLinks.FirstOrDefault()?.BreadcrumbLocation;
    var response = shadow.GenerateFakeCsvData(canary.Name, "customer_export.csv", breadcrumb);
    var payload = string.IsNullOrWhiteSpace(bodyText) ? "SELECT * FROM customers LIMIT 100;" : bodyText;
    var ip = ExtractClientIp(context);
    var userAgent = ResolveUserAgent(context, "psql (PostgreSQL) 16.1");
    var path = context.Request.Path.ToString();

    QueueShadowCapture(scopeFactory, canary.Id, canary.Type, ip, userAgent, path, payload, response, isExfiltration: true);
    return Results.Content(response, "text/plain");
});

app.MapPost("/api/shadow/k8s/{tokenId:guid}", async (
    Guid tokenId,
    HttpContext context,
    ShadowLureDbContext db,
    IShadowEngine shadow,
    IServiceScopeFactory scopeFactory) =>
{
    var canary = await FindCanaryAsync(db, tokenId);
    if (canary == null)
    {
        return Results.NotFound("Kubernetes secret not found");
    }

    var response = shadow.GenerateDbQueryResponse("kubectl get secrets -A", canary.OutgoingLinks.FirstOrDefault()?.BreadcrumbLocation);
    var ip = ExtractClientIp(context);
    var userAgent = ResolveUserAgent(context, "kubectl/v1.30 (linux/amd64)");
    var path = context.Request.Path.ToString();

    QueueShadowCapture(scopeFactory, canary.Id, canary.Type, ip, userAgent, path, "kubectl get secrets -A -o yaml", response, isExfiltration: false);
    return Results.Content(response, "text/plain");
});

app.MapPost("/api/shadow/api/{tokenId:guid}", async (
    Guid tokenId,
    HttpContext context,
    ShadowLureDbContext db,
    IShadowEngine shadow,
    IServiceScopeFactory scopeFactory) =>
{
    var canary = await FindCanaryAsync(db, tokenId);
    if (canary == null)
    {
        return Results.NotFound("API token rejected");
    }

    var response = shadow.GenerateDbQueryResponse("GET /v1/internal/invoices", canary.OutgoingLinks.FirstOrDefault()?.BreadcrumbLocation);
    var ip = ExtractClientIp(context);
    var userAgent = ResolveUserAgent(context, "python-requests/2.32");
    var path = context.Request.Path.ToString();

    QueueShadowCapture(scopeFactory, canary.Id, canary.Type, ip, userAgent, path, "GET /v1/internal/invoices?tenant=enterprise", response, isExfiltration: false);
    return Results.Content(response, "text/plain");
});

app.MapPost("/api/simulate/step", async (
    HttpContext context,
    ShadowLureDbContext db,
    IShadowEngine shadow,
    IBehavioralProfiler profiler,
    ILlmService llm,
    IAlertNotifier alert) =>
{
    var canaries = await db.CanaryTokens
        .Include(c => c.OutgoingLinks).ThenInclude(l => l.TargetCanary)
        .OrderBy(c => c.CreatedAt)
        .ToListAsync();

    if (canaries.Count == 0)
    {
        await SeedWorkspaceAsync(db);
        canaries = await db.CanaryTokens
            .Include(c => c.OutgoingLinks).ThenInclude(l => l.TargetCanary)
            .OrderBy(c => c.CreatedAt)
            .ToListAsync();
    }

    var eventCount = await db.TriggerEvents.CountAsync();
    var canary = canaries[eventCount % canaries.Count];
    var (payload, response, userAgent, exfil) = BuildSimulationStep(canary, shadow);
    var ip = ExtractClientIp(context);

    // userAgent here is deliberately the simulated tool's signature, not the
    // operator's real browser UA - see ResolveUserAgent's doc comment for why
    // that distinction matters for this specific call site.
    await CaptureShadowEventAsync(db, profiler, llm, alert, canary.Id, ip, userAgent, context.Request.Path.ToString(), payload, response, exfil);
    return Results.Redirect($"/?key={Uri.EscapeDataString(operatorApiKey)}");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapPost("/api/simulate/full", async (
    HttpContext context,
    ShadowLureDbContext db,
    IShadowEngine shadow,
    IBehavioralProfiler profiler,
    ILlmService llm,
    IAlertNotifier alert) =>
{
    var canaries = await db.CanaryTokens
        .Include(c => c.OutgoingLinks).ThenInclude(l => l.TargetCanary)
        .OrderBy(c => c.CreatedAt)
        .ToListAsync();

    var ip = ExtractClientIp(context);
    foreach (var canary in canaries.Take(4))
    {
        var (payload, response, userAgent, exfil) = BuildSimulationStep(canary, shadow);
        await CaptureShadowEventAsync(db, profiler, llm, alert, canary.Id, ip, userAgent, context.Request.Path.ToString(), payload, response, exfil);
        await Task.Delay(60);
    }

    return Results.Redirect($"/?key={Uri.EscapeDataString(operatorApiKey)}");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapPost("/api/reset", async (ShadowLureDbContext db) =>
{
    db.TriggerEvents.RemoveRange(db.TriggerEvents);
    db.AttackerSessions.RemoveRange(db.AttackerSessions);
    db.CanaryLinks.RemoveRange(db.CanaryLinks);
    db.CanaryTokens.RemoveRange(db.CanaryTokens);
    await db.SaveChangesAsync();
    await SeedWorkspaceAsync(db);
    return Results.Redirect($"/?key={Uri.EscapeDataString(operatorApiKey)}");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/api/cockpit/stats", async (ShadowLureDbContext db) =>
{
    var snapshot = await LoadDashboardSnapshotAsync(db);
    var canaries = snapshot.Canaries;
    var session = snapshot.Session;
    var triggeredCanaries = canaries.Count(c => c.Status == TokenStatus.Triggered);
    var riskScore = session?.RiskScore ?? 0;
    var riskLevel = (session?.RiskLevel ?? "Low").ToUpperInvariant();
    var attackerIp = session?.AttackerIp ?? "No active session";
    var chainDepth = session?.MaxChainDepth ?? 0;
    var exfilAttempts = session?.DataExfilAttempts ?? 0;
    var automationText = session?.AutomationDetected == true ? "Detected" : "Not observed";
    var summary = session?.LlmProfileSummary ?? "No attacker has touched the decoy chain yet. ShadowLure is waiting for the first high-signal mistake.";

    return Results.Json(new
    {
        triggered = triggeredCanaries.ToString(),
        exfil = exfilAttempts.ToString(),
        automation = automationText,
        riskScore,
        riskLevel,
        chainDepth,
        attackerIp,
        summary,
        tableHtml = RenderCanaryTablePartial(canaries)
    });
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/api/attacker/details", async (ShadowLureDbContext db) =>
{
    var session = await db.AttackerSessions
        .Include(s => s.Events).ThenInclude(e => e.CanaryToken)
        .OrderByDescending(s => s.LastSeen)
        .FirstOrDefaultAsync();

    return Results.Content(RenderAttackerDossierModalPartial(session), "text/html");
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.MapGet("/api/events/stream", async (HttpContext context, ShadowLureDbContext db) =>
{
    context.Response.Headers.Append("Content-Type", "text/event-stream");
    context.Response.Headers.Append("Cache-Control", "no-cache");
    context.Response.Headers.Append("Connection", "keep-alive");

    var lastEventId = Guid.Empty;
    while (!context.RequestAborted.IsCancellationRequested)
    {
        // AsNoTracking is required here, not just a micro-optimization: this loop
        // reuses one request-scoped DbContext for the lifetime of the SSE
        // connection (which can be open for hours). Without it, every polled
        // TriggerEvent/CanaryToken gets added to the change tracker and is never
        // released, so a long-lived dashboard tab leaks memory a little more with
        // every 2-second poll.
        var latestEvent = await db.TriggerEvents
            .AsNoTracking()
            .Include(e => e.CanaryToken)
            .OrderByDescending(e => e.TriggeredAt)
            .FirstOrDefaultAsync();

        if (latestEvent != null && latestEvent.Id != lastEventId)
        {
            lastEventId = latestEvent.Id;
            var html = RenderEventCard(latestEvent, compact: true).Replace("\r", string.Empty).Replace("\n", string.Empty);
            await context.Response.WriteAsync($"data: {html}\n\n");
            await context.Response.Body.FlushAsync();
        }

        await Task.Delay(2000, context.RequestAborted);
    }
}).AddEndpointFilter(RequireOperatorKeyAsync);

app.Run();

async Task<DashboardSnapshot> LoadDashboardSnapshotAsync(ShadowLureDbContext db)
{
    var workspace = await db.Workspaces.OrderBy(w => w.CreatedAt).FirstAsync();
    var canaries = await db.CanaryTokens
        .Where(c => c.WorkspaceId == workspace.Id)
        .Include(c => c.OutgoingLinks).ThenInclude(l => l.TargetCanary)
        .OrderBy(c => c.CreatedAt)
        .ToListAsync();

    var events = await db.TriggerEvents
        .Include(e => e.CanaryToken)
        .OrderByDescending(e => e.TriggeredAt)
        .Take(20)
        .ToListAsync();

    var session = await db.AttackerSessions
        .Where(s => s.WorkspaceId == workspace.Id)
        .Include(s => s.Events)
        .OrderByDescending(s => s.LastSeen)
        .FirstOrDefaultAsync();

    var links = await db.CanaryLinks.ToListAsync();

    return new DashboardSnapshot(workspace, canaries, links, events, session);
}

async Task SeedWorkspaceAsync(ShadowLureDbContext db)
{
    var workspace = await db.Workspaces.OrderBy(w => w.CreatedAt).FirstOrDefaultAsync();
    if (workspace == null)
    {
        workspace = new Workspace
        {
            Name = "Acme Cloud Production",
            ApiKey = "sl_live_94f8a12b0e454a"
        };
        db.Workspaces.Add(workspace);
        await db.SaveChangesAsync();
    }

    if (await db.CanaryTokens.AnyAsync(c => c.WorkspaceId == workspace.Id))
    {
        return;
    }

    var now = DateTime.UtcNow;
    var aws = new CanaryToken
    {
        Id = Guid.Parse("c2d77a06-444f-4eb8-b9a3-577823fcae6d"),
        WorkspaceId = workspace.Id,
        Name = "prod-s3-replication-key",
        Type = TokenType.AwsKey,
        TargetService = "AWS S3",
        DecoyValue = "AKIAQ4SHADOWLURE7X2K3",
        ContextInfo = "Placed inside a fake CI artifact and Terraform output",
        CreatedAt = now.AddMinutes(-18)
    };

    var dbToken = new CanaryToken
    {
        Id = Guid.Parse("e5f1b2c3-8899-4d5e-a1b2-3c4d5e6f7a8b"),
        WorkspaceId = workspace.Id,
        Name = "customer-ledger-readonly",
        Type = TokenType.DbConnection,
        TargetService = "PostgreSQL",
        DecoyValue = "postgresql://ledger_ro:P%40ssw0rd-rotated@prod-ledger.internal:5432/customers",
        ContextInfo = "Revealed only after S3 enumeration",
        CreatedAt = now.AddMinutes(-14)
    };

    var k8s = new CanaryToken
    {
        Id = Guid.Parse("f6a7b8c9-0011-4223-b334-5d6e7f8a9b0c"),
        WorkspaceId = workspace.Id,
        Name = "eks-payments-secret",
        Type = TokenType.K8sSecret,
        TargetService = "Kubernetes",
        DecoyValue = "payments/prod/service-account-token",
        ContextInfo = "Embedded in the fake database backup metadata",
        CreatedAt = now.AddMinutes(-9)
    };

    var api = new CanaryToken
    {
        Id = Guid.Parse("a1b2c3d4-e5f6-4789-8012-3456789abcde"),
        WorkspaceId = workspace.Id,
        Name = "internal-billing-api-token",
        Type = TokenType.ApiKey,
        TargetService = "Internal API",
        DecoyValue = "shl_api_live_ef3c2bb1b9524b8f9a1f",
        ContextInfo = "Final breadcrumb for high-confidence intent capture",
        CreatedAt = now.AddMinutes(-5)
    };

    db.CanaryTokens.AddRange(aws, dbToken, k8s, api);
    db.CanaryLinks.AddRange(
        new CanaryLink
        {
            SourceCanary = aws,
            TargetCanary = dbToken,
            Description = "S3 backup exposes database connection string",
            BreadcrumbLocation = "s3://prod-s3-replication/backups/customer-ledger.env"
        },
        new CanaryLink
        {
            SourceCanary = dbToken,
            TargetCanary = k8s,
            Description = "CSV export hints at Kubernetes secret",
            BreadcrumbLocation = "k8s://payments/prod/eks-payments-secret"
        },
        new CanaryLink
        {
            SourceCanary = k8s,
            TargetCanary = api,
            Description = "Service account references internal billing API",
            BreadcrumbLocation = "https://billing.internal/v1/invoices"
        });

    await db.SaveChangesAsync();
}

async Task<CanaryToken?> FindCanaryAsync(ShadowLureDbContext db, Guid tokenId)
{
    return await db.CanaryTokens
        .Include(c => c.OutgoingLinks).ThenInclude(l => l.TargetCanary)
        .FirstOrDefaultAsync(c => c.Id == tokenId);
}

string ExtractClientIp(HttpContext context)
{
    var ip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
        ?? context.Request.Headers["X-Real-IP"].FirstOrDefault()
        ?? context.Connection.RemoteIpAddress?.ToString();
    return string.IsNullOrWhiteSpace(ip) ? "127.0.0.1" : ip;
}

// For real shadow-trap traffic, the caller's own User-Agent (aws-cli, psql,
// curl, ...) is what we want to record, falling back to a representative
// default only if the request didn't send one. Simulate-endpoint callers pass
// the simulated tool's UA directly instead of routing through this - using the
// operator's own browser UA there would misclassify every "Trigger Step" demo
// event as "Browser / HTTP Client" instead of the tool it's supposed to simulate.
string ResolveUserAgent(HttpContext context, string fallbackUserAgent)
{
    var userAgent = context.Request.Headers.UserAgent.ToString();
    return string.IsNullOrWhiteSpace(userAgent) ? fallbackUserAgent : userAgent;
}

// Fires the actual capture/profiling/alerting/LLM-summary pipeline in the
// background, off its own DI scope, and returns immediately. This is used only
// by the /api/shadow/* trap endpoints: those endpoints exist to hand a
// believable, fast decoy response to whoever just used a leaked credential, and
// the old implementation awaited a DB write + Slack webhook + Groq LLM call
// before returning that response - meaning a real S3/psql/kubectl client would
// see multi-second latency where a genuine service responds in milliseconds,
// which is exactly the kind of tell that gives a deception platform away to a
// careful attacker. The capture logic itself (CaptureShadowEventAsync) is
// unchanged and still fully persisted; only the response no longer waits on it.
void QueueShadowCapture(
    IServiceScopeFactory scopeFactory,
    Guid canaryId,
    TokenType tokenType,
    string ip,
    string userAgent,
    string requestPath,
    string requestPayload,
    string responsePayload,
    bool isExfiltration)
{
    _ = Task.Run(async () =>
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var scopedDb = scope.ServiceProvider.GetRequiredService<ShadowLureDbContext>();
            var scopedProfiler = scope.ServiceProvider.GetRequiredService<IBehavioralProfiler>();
            var scopedLlm = scope.ServiceProvider.GetRequiredService<ILlmService>();
            var scopedAlert = scope.ServiceProvider.GetRequiredService<IAlertNotifier>();

            var trigger = await CaptureShadowEventAsync(
                scopedDb, scopedProfiler, scopedLlm, scopedAlert,
                canaryId, ip, userAgent, requestPath, requestPayload, responsePayload, isExfiltration);

            if (isExfiltration)
            {
                MetricsService.DataExfiltrationAttemptsTotal.Inc();
            }
            MetricsService.CanaryTriggersTotal.WithLabels(tokenType.ToString(), trigger.SimulatedTool, trigger.AttackerSession?.RiskLevel ?? "Low").Inc();
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Background shadow-event capture failed for canary {CanaryId}", canaryId);
        }
    });
}

async Task<TriggerEvent> CaptureShadowEventAsync(
    ShadowLureDbContext db,
    IBehavioralProfiler profiler,
    ILlmService llm,
    IAlertNotifier alert,
    Guid canaryId,
    string ip,
    string userAgent,
    string requestPath,
    string requestPayload,
    string responsePayload,
    bool isExfiltration = false)
{
    var canary = await db.CanaryTokens.FirstOrDefaultAsync(c => c.Id == canaryId)
        ?? throw new InvalidOperationException($"Canary {canaryId} was deleted before its trigger event could be captured.");

    canary.TriggerCount++;
    canary.Status = TokenStatus.Triggered;

    var fingerprint = profiler.GenerateFingerprint(ip, userAgent);
    var session = await db.AttackerSessions
        .Include(s => s.Events)
        .FirstOrDefaultAsync(s => s.Fingerprint == fingerprint);

    if (session == null)
    {
        session = new AttackerSession
        {
            WorkspaceId = canary.WorkspaceId,
            Fingerprint = fingerprint,
            AttackerIp = ip,
            UserAgent = userAgent,
            FirstSeen = DateTime.UtcNow
        };
        db.AttackerSessions.Add(session);
        MetricsService.ActiveAttackerSessions.Inc();
    }

    session.LastSeen = DateTime.UtcNow;
    session.AutomationDetected = profiler.IsAutomationTool(userAgent, session.Events);
    if (isExfiltration)
    {
        session.DataExfilAttempts++;
    }

    var triggerEvent = new TriggerEvent
    {
        CanaryTokenId = canary.Id,
        AttackerSession = session,
        AttackerIp = ip,
        UserAgent = userAgent,
        RequestMethod = "POST",
        RequestPath = requestPath,
        RequestPayload = requestPayload,
        ResponsePayload = responsePayload,
        SimulatedTool = profiler.DetectToolSignature(userAgent, requestPath),
        IsAutomationScript = session.AutomationDetected
    };

    db.TriggerEvents.Add(triggerEvent);
    session.Events.Add(triggerEvent);
    triggerEvent.ChainDepth = session.Events.Count;
    session.MaxChainDepth = Math.Max(session.MaxChainDepth, triggerEvent.ChainDepth);

    // Single source of truth for the risk formula - this used to be reimplemented
    // inline here, duplicating (and risking drifting from) BehavioralProfiler.CalculateRisk.
    var (score, level) = profiler.CalculateRisk(session);
    session.RiskScore = score;
    session.RiskLevel = level;

    await db.SaveChangesAsync();

    var workspace = await db.Workspaces.FindAsync(canary.WorkspaceId);
    if (workspace != null && !string.IsNullOrWhiteSpace(workspace.SlackWebhookUrl))
    {
        await alert.SendTriggerAlertAsync(triggerEvent, canary, session, workspace.SlackWebhookUrl);
    }

    var summary = $"IP={ip}; tool={triggerEvent.SimulatedTool}; payload={requestPayload}; chain_depth={triggerEvent.ChainDepth}; exfil_attempts={session.DataExfilAttempts}; automation={session.AutomationDetected}";
    session.LlmProfileSummary = await llm.GenerateAttackerProfileAsync(summary);
    await db.SaveChangesAsync();

    return triggerEvent;
}

async Task<string> ReadBodyAsync(HttpContext context)
{
    // Shadow endpoints are the one part of the app deliberately exposed to
    // untrusted/attacker traffic. Without a cap, ReadToEndAsync() on the raw
    // body stream lets anyone who finds a token GUID (or brute-forces one) send
    // an effectively unbounded POST body and exhaust server memory. 64 KB is
    // far more than any realistic aws-cli/psql/kubectl request body.
    const int maxBodyBytes = 64 * 1024;
    using var reader = new StreamReader(context.Request.Body);
    var buffer = new char[maxBodyBytes];
    var read = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
    return new string(buffer, 0, read);
}

// Endpoint filter applied to every operator-only route - both the mutating
// ones (deploy/revoke canary, reset workspace, run simulations) and, since the
// dashboard exposes real captured attacker IPs/payloads and decoy credential
// values, every read route too (dashboard page, canary details, forensic
// dossier, graph/stats JSON, SSE stream, /metrics). Only /api/shadow/* stays
// open - attackers must be able to reach those without credentials.
//
// The key can arrive three ways, checked in this order:
//   1. X-Operator-Key header - what the dashboard's own HTMX requests send,
//      via the hx-headers attribute on <body>.
//   2. A "key" form field - what the three plain <form method="post"> actions
//      send, since htmx headers don't apply to native browser form submissions.
//   3. A "key" query string parameter - required for GET /, because a plain
//      browser navigation can't attach a custom header, and for the SSE
//      stream, because the native EventSource API can't attach one either.
//      The dashboard's own links/fetch calls/SSE connection all carry it this
//      way once the page itself has loaded with a valid key.
async ValueTask<object?> RequireOperatorKeyAsync(EndpointFilterInvocationContext efic, EndpointFilterDelegate next)
{
    var request = efic.HttpContext.Request;
    var provided = request.Headers["X-Operator-Key"].FirstOrDefault();

    if (string.IsNullOrEmpty(provided) && request.HasFormContentType)
    {
        var form = await request.ReadFormAsync();
        provided = form["key"].FirstOrDefault();
    }

    if (string.IsNullOrEmpty(provided))
    {
        provided = request.Query["key"].FirstOrDefault();
    }

    if (!string.Equals(provided, operatorApiKey, StringComparison.Ordinal))
    {
        return Results.Text(
            "Unauthorized. Provide the operator key via an X-Operator-Key header or a ?key= query parameter.",
            "text/plain",
            statusCode: StatusCodes.Status401Unauthorized);
    }

    return await next(efic);
}

(string Payload, string Response, string UserAgent, bool Exfiltration) BuildSimulationStep(CanaryToken canary, IShadowEngine shadow)
{
    var breadcrumb = canary.OutgoingLinks.FirstOrDefault()?.BreadcrumbLocation;
    return canary.Type switch
    {
        TokenType.AwsKey => (
            "aws s3 ls --recursive s3://prod-s3-replication",
            shadow.GenerateS3BucketListing(canary.Name, breadcrumb),
            "aws-cli/2.15.10 Python/3.11.6 Linux/6.5",
            false),
        TokenType.DbConnection => (
            "SELECT * FROM customers LIMIT 100;",
            shadow.GenerateFakeCsvData(canary.Name, "customer_export.csv", breadcrumb),
            "psql (PostgreSQL) 16.1",
            true),
        TokenType.K8sSecret => (
            "kubectl get secrets -A -o yaml",
            shadow.GenerateDbQueryResponse("kubectl get secrets -A", breadcrumb),
            "kubectl/v1.30 (linux/amd64)",
            false),
        _ => (
            "GET /v1/internal/invoices?tenant=enterprise",
            shadow.GenerateDbQueryResponse("GET /v1/internal/invoices", breadcrumb),
            "python-requests/2.32",
            false)
    };
}

string RenderFullDashboardHtml(DashboardSnapshot snapshot)
{
    var canaries = snapshot.Canaries;
    var events = snapshot.Events;
    var session = snapshot.Session;
    var totalCanaries = canaries.Count;
    var triggeredCanaries = canaries.Count(c => c.Status == TokenStatus.Triggered);
    var riskScore = session?.RiskScore ?? 0;
    var riskLevel = (session?.RiskLevel ?? "Low").ToUpperInvariant();
    var attackerIp = session?.AttackerIp ?? "No active session";
    var chainDepth = session?.MaxChainDepth ?? 0;
    var exfilAttempts = session?.DataExfilAttempts ?? 0;
    var automationText = session?.AutomationDetected == true ? "Detected" : "Not observed";
    var summary = session?.LlmProfileSummary ?? "No attacker has touched the decoy chain yet. ShadowLure is waiting for the first high-signal mistake.";

    return $$"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ShadowLure &mdash; Active Deception Platform</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://unpkg.com/htmx.org@1.9.10"></script>
        <script src="https://unpkg.com/htmx.org@1.9.10/dist/ext/sse.js"></script>
        <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <script src="https://unpkg.com/lenis@1.1.13/dist/lenis.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/ScrollTrigger.min.js"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root { color-scheme: dark; }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            html { scroll-behavior: auto; }
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: #050505;
                color: #ededed;
                overflow-x: hidden;
                -webkit-font-smoothing: antialiased;
            }
            .mono { font-family: 'JetBrains Mono', monospace; }
            .shell { max-width: 1720px; width: 100%; margin: 0 auto; padding: 0 3rem; }

            /* Nav */
            .nav {
                position: fixed; top: 0; left: 0; right: 0; z-index: 100;
                border-bottom: 1px solid rgba(255,255,255,0.06);
                background: rgba(5,5,5,0.75);
                backdrop-filter: blur(20px) saturate(1.8);
                -webkit-backdrop-filter: blur(20px) saturate(1.8);
            }

            /* Hero */
            .hero {
                position: relative;
                min-height: 100vh;
                display: flex;
                align-items: center;
                overflow: hidden;
            }
            .hero-grid-bg {
                position: absolute; inset: 0;
                background-image:
                    radial-gradient(circle at 1px 1px, rgba(255,255,255,0.04) 1px, transparent 0);
                background-size: 40px 40px;
            }
            .hero-glow {
                position: absolute; width: 600px; height: 600px;
                border-radius: 50%;
                filter: blur(120px);
                opacity: 0.35;
                pointer-events: none;
            }
            .hero-glow-1 { top: -10%; left: 15%; background: #2dd4bf; }
            .hero-glow-2 { bottom: -15%; right: 10%; background: #7c3aed; }
            .hero-glow-3 { top: 40%; left: 55%; background: #fb7185; width: 400px; height: 400px; opacity: 0.2; }

            .hero-title {
                font-size: clamp(2.8rem, 5.2vw, 5rem);
                font-weight: 900;
                line-height: 0.98;
                letter-spacing: -0.04em;
                background: linear-gradient(135deg, #ffffff 0%, #a1a1aa 40%, #2dd4bf 70%, #7c3aed 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .hero-sub {
                font-size: clamp(1rem, 1.5vw, 1.25rem);
                line-height: 1.7;
                color: #8a8a93;
                max-width: 640px;
            }
            .hero-badge {
                display: inline-flex; align-items: center; gap: 0.5rem;
                padding: 0.4rem 1rem;
                border-radius: 9999px;
                border: 1px solid rgba(45, 212, 191, 0.3);
                background: rgba(45, 212, 191, 0.08);
                font-size: 0.8rem; font-weight: 600;
                color: #5eead4;
            }
            .hero-badge-dot {
                width: 6px; height: 6px; border-radius: 50%;
                background: #2dd4bf;
                box-shadow: 0 0 12px #2dd4bf;
                animation: pulse-dot 2s infinite;
            }
            @keyframes pulse-dot {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.4; }
            }

            /* Buttons */
            .btn-hero {
                display: inline-flex; align-items: center; gap: 0.6rem;
                padding: 0.85rem 2rem;
                border-radius: 10px;
                font-size: 0.95rem; font-weight: 700;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                cursor: pointer;
            }
            .btn-hero-primary {
                background: #fff; color: #000;
                box-shadow: 0 0 0 1px rgba(255,255,255,0.1), 0 8px 40px rgba(255,255,255,0.1);
            }
            .btn-hero-primary:hover { transform: translateY(-2px); box-shadow: 0 0 0 1px rgba(255,255,255,0.2), 0 16px 60px rgba(255,255,255,0.15); }
            .btn-hero-secondary {
                background: rgba(255,255,255,0.06); color: #e4e4e7;
                border: 1px solid rgba(255,255,255,0.1);
            }
            .btn-hero-secondary:hover { background: rgba(255,255,255,0.12); transform: translateY(-2px); }
            .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem; border-radius: 8px; font-size: 0.8rem; font-weight: 600; transition: all 0.2s; cursor: pointer; }
            .btn-primary { background: #fff; color: #000; }
            .btn-primary:hover { background: #e5e5e5; }
            .btn-ghost { background: rgba(255,255,255,0.05); color: #fff; border: 1px solid rgba(255,255,255,0.08); }
            .btn-ghost:hover { background: rgba(255,255,255,0.1); }

            /* Section styling */
            .section-label {
                display: inline-flex; align-items: center; gap: 0.5rem;
                font-size: 0.75rem; font-weight: 700; letter-spacing: 0.08em;
                text-transform: uppercase;
                color: #2dd4bf;
            }
            .section-title {
                font-size: clamp(2.2rem, 4.5vw, 3.5rem);
                font-weight: 800;
                letter-spacing: -0.03em;
                line-height: 1.1;
            }
            .section-desc {
                font-size: 1.1rem; line-height: 1.8; color: #71717a; max-width: 620px;
            }

            /* Cards */
            .feature-card {
                background: rgba(255,255,255,0.03);
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 16px;
                padding: 2.5rem;
                transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative; overflow: hidden;
            }
            .feature-card::before {
                content: '';
                position: absolute; top: 0; left: 0; right: 0; height: 1px;
                background: linear-gradient(90deg, transparent, rgba(45,212,191,0.4), transparent);
                opacity: 0;
                transition: opacity 0.4s;
            }
            .feature-card:hover { border-color: rgba(255,255,255,0.12); transform: translateY(-4px); }
            .feature-card:hover::before { opacity: 1; }
            .feature-icon {
                width: 48px; height: 48px; border-radius: 12px;
                display: grid; place-items: center;
                background: rgba(45,212,191,0.1);
                border: 1px solid rgba(45,212,191,0.2);
                margin-bottom: 1.5rem;
            }

            /* Dashboard Panel */
            .panel {
                background: rgba(17,17,21,0.8);
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 14px;
                backdrop-filter: blur(8px);
            }
            .risk-ring {
                width: 72px; height: 72px; border-radius: 50%;
                display: grid; place-items: center;
                background: conic-gradient(#fb7185 calc({{riskScore}} * 1%), rgba(255,255,255,0.08) 0);
            }
            .risk-ring-inner {
                width: 58px; height: 58px; border-radius: 50%;
                background: #111115; display: grid; place-items: center;
            }

            /* Animations */
            .reveal { opacity: 0; transform: translateY(40px); }
            .reveal-left { opacity: 0; transform: translateX(-40px); }
            .reveal-right { opacity: 0; transform: translateX(40px); }
            .stagger-item { opacity: 0; transform: translateY(30px); }

            /* Divider */
            .gradient-line {
                height: 1px;
                background: linear-gradient(90deg, transparent, rgba(45,212,191,0.3), rgba(124,58,237,0.3), transparent);
            }

            @media (max-width: 768px) {
                .shell { padding: 0 1rem; }
                .hero-title { font-size: 3rem; }
            }
        </style>
    </head>
    <body hx-headers='{"X-Operator-Key": "{{EncodeForSingleQuotedJsonAttribute(operatorApiKey)}}"}'>
        <!-- NAV -->
        <nav class="nav">
            <div class="shell flex items-center justify-between py-3.5">
                <div class="flex items-center gap-6">
                    <a href="/?key={{E(Uri.EscapeDataString(operatorApiKey))}}" class="text-lg font-bold tracking-tight text-white hover:text-teal-300 transition-colors">
                        ShadowLure
                    </a>
                    <div class="hidden md:flex items-center gap-5">
                        <a href="#features" class="text-sm text-zinc-500 hover:text-zinc-200 transition-colors">Features</a>
                        <a href="#cockpit" class="text-sm text-zinc-500 hover:text-zinc-200 transition-colors">Cockpit</a>
                        <a href="#architecture" class="text-sm text-zinc-500 hover:text-zinc-200 transition-colors">Architecture</a>
                        <a href="/metrics?key={{E(Uri.EscapeDataString(operatorApiKey))}}" target="_blank" class="text-sm text-zinc-500 hover:text-amber-300 mono transition-colors">/metrics</a>
                    </div>
                </div>
                <div class="flex items-center gap-2.5">
                    <button hx-get="/api/canaries/modal" hx-target="#modal-container" hx-swap="innerHTML" class="btn btn-primary text-xs">Deploy Canary</button>
                </div>
            </div>
        </nav>

        <!-- HERO -->
        <section class="hero">
            <div class="hero-grid-bg"></div>
            <div class="hero-glow hero-glow-1"></div>
            <div class="hero-glow hero-glow-2"></div>
            <div class="hero-glow hero-glow-3"></div>
            <div class="shell relative z-10 pt-28 pb-16 w-full">
                <div class="grid lg:grid-cols-12 gap-12 items-center min-h-[calc(100vh-140px)]">
                    <!-- Left Column -->
                    <div class="lg:col-span-7">
                        <div class="hero-badge mb-6 reveal">
                            <span class="hero-badge-dot"></span>
                            Active Deception Platform
                        </div>
                        <h1 class="hero-title reveal">Turn leaked<br>credentials into<br>controlled traps.</h1>
                        <p class="hero-sub mt-6 reveal">
                            ShadowLure transforms stolen credentials into instrumented shadow environments. Every attacker touch is profiled, every lateral movement is mapped, every exfiltration attempt generates evidence.
                        </p>
                        <div class="flex flex-wrap gap-4 mt-8 reveal">
                            <a href="#cockpit" class="btn-hero btn-hero-primary">
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                                Launch Cockpit
                            </a>
                            <form action="/api/simulate/full" method="post">
                                <input type="hidden" name="key" value="{{E(operatorApiKey)}}">
                                <button class="btn-hero btn-hero-secondary" type="submit">
                                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>
                                    Run Full Attack Simulation
                                </button>
                            </form>
                        </div>
                        <div class="grid grid-cols-3 gap-8 mt-12 max-w-lg border-t border-white/5 pt-8">
                            <div class="reveal">
                                <div class="mono text-3xl font-black text-teal-300">{{totalCanaries}}</div>
                                <div class="text-xs text-zinc-500 mt-1">Active Decoys</div>
                            </div>
                            <div class="reveal">
                                <div class="mono text-3xl font-black text-rose-300">{{events.Count}}</div>
                                <div class="text-xs text-zinc-500 mt-1">Captured Events</div>
                            </div>
                            <div class="reveal">
                                <div class="mono text-3xl font-black text-amber-300">{{chainDepth}}</div>
                                <div class="text-xs text-zinc-500 mt-1">Max Chain Depth</div>
                            </div>
                        </div>
                    </div>

                    <!-- Right Column: Widescreen Status Widget -->
                    <div class="lg:col-span-5 reveal">
                        <div class="panel p-7 border border-white/10 shadow-2xl bg-black/60 relative overflow-hidden">
                            <div class="flex items-center justify-between border-b border-white/10 pb-4 mb-6">
                                <div class="flex items-center gap-2">
                                    <span class="w-2.5 h-2.5 rounded-full bg-teal-400 animate-ping"></span>
                                    <span class="mono text-xs font-bold uppercase tracking-wider text-teal-300">Live Deception Engine</span>
                                </div>
                                <span class="mono text-[11px] text-zinc-500">{{E(snapshot.Workspace.ApiKey)}}</span>
                            </div>

                            <div class="grid grid-cols-2 gap-4 mb-6">
                                <div class="p-4 rounded-xl bg-white/5 border border-white/5">
                                    <div class="text-[10px] font-bold uppercase tracking-wider text-zinc-500 mb-1">Engine Status</div>
                                    <div class="mono text-sm font-bold text-teal-300 flex items-center gap-2">
                                        <span class="w-2 h-2 rounded-full bg-teal-400"></span> Listening
                                    </div>
                                </div>
                                <div class="p-4 rounded-xl bg-white/5 border border-white/5">
                                    <div class="text-[10px] font-bold uppercase tracking-wider text-zinc-500 mb-1">Attacker Risk Score</div>
                                    <div class="mono text-sm font-bold text-rose-400">
                                        {{riskLevel}} {{riskScore}}/100
                                    </div>
                                </div>
                            </div>

                            <div class="space-y-3 font-mono text-xs">
                                <div class="p-3 rounded-lg bg-black/50 border border-white/5 flex items-center justify-between">
                                    <span class="text-zinc-400">Target Environment:</span>
                                    <span class="text-teal-300 font-semibold">AWS / K8s / PostgreSQL</span>
                                </div>
                                <div class="p-3 rounded-lg bg-black/50 border border-white/5 flex items-center justify-between">
                                    <span class="text-zinc-400">Active Attacker IP:</span>
                                    <span class="text-amber-300 font-semibold">{{E(attackerIp)}}</span>
                                </div>
                                <div class="p-3 rounded-lg bg-black/50 border border-white/5 flex items-center justify-between">
                                    <span class="text-zinc-400">Data Lures Served:</span>
                                    <span class="text-rose-300 font-semibold">{{exfilAttempts}} Exfil lures</span>
                                </div>
                            </div>

                            <div class="mt-6 pt-4 border-t border-white/5 flex items-center justify-between text-xs text-zinc-500">
                                <span class="flex items-center gap-1.5">
                                    <svg class="w-3.5 h-3.5 text-teal-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                    Zero False Positive Guarantee
                                </span>
                                <a href="#cockpit" class="text-teal-400 hover:text-teal-300 font-semibold">View Cockpit &rarr;</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <div class="gradient-line"></div>

        <!-- FEATURES / HOW IT WORKS -->
        <section id="features" class="py-32">
            <div class="shell">
                <div class="text-center mb-20">
                    <div class="section-label justify-center reveal">
                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                        How it works
                    </div>
                    <h2 class="section-title mt-5 reveal">Beyond passive canaries.<br>Active deception chains.</h2>
                    <p class="section-desc mx-auto mt-6 reveal">
                        Passive canaries fire one alert. ShadowLure keeps the adversary moving through a controlled, instrumented path â€” each step raising confidence and capturing forensic evidence.
                    </p>
                </div>
                <div class="grid md:grid-cols-2 lg:grid-cols-4 gap-5">
                    <div class="feature-card stagger-item">
                        <div class="feature-icon">
                            <svg class="w-5 h-5 text-teal-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/></svg>
                        </div>
                        <h3 class="text-lg font-bold mb-2">Seed</h3>
                        <p class="text-sm text-zinc-500 leading-relaxed">Deploy fake AWS keys, database strings, K8s secrets, and API tokens that match your real environment naming.</p>
                    </div>
                    <div class="feature-card stagger-item">
                        <div class="feature-icon" style="background:rgba(251,191,36,0.1);border-color:rgba(251,191,36,0.2)">
                            <svg class="w-5 h-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/></svg>
                        </div>
                        <h3 class="text-lg font-bold mb-2">Engage</h3>
                        <p class="text-sm text-zinc-500 leading-relaxed">When bait is used, respond with believable S3 listings, CSV data, and query results instead of closing the connection.</p>
                    </div>
                    <div class="feature-card stagger-item">
                        <div class="feature-icon" style="background:rgba(124,58,237,0.1);border-color:rgba(124,58,237,0.2)">
                            <svg class="w-5 h-5 text-violet-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                        </div>
                        <h3 class="text-lg font-bold mb-2">Profile</h3>
                        <p class="text-sm text-zinc-500 leading-relaxed">Fingerprint attacker tools, detect automation, measure chain depth, and calculate risk scores in real time.</p>
                    </div>
                    <div class="feature-card stagger-item">
                        <div class="feature-icon" style="background:rgba(251,113,133,0.1);border-color:rgba(251,113,133,0.2)">
                            <svg class="w-5 h-5 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>
                        </div>
                        <h3 class="text-lg font-bold mb-2">Respond</h3>
                        <p class="text-sm text-zinc-500 leading-relaxed">Generate LLM-powered threat intelligence summaries and push real-time alerts to Slack, webhooks, and SIEM.</p>
                    </div>
                </div>
            </div>
        </section>

        <div class="gradient-line"></div>

        <!-- COCKPIT / DASHBOARD -->
        <section id="cockpit" class="py-24 relative">
            <div class="shell">
                <div class="mb-12">
                    <div class="section-label reveal">
                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z"/></svg>
                        Operator Cockpit
                    </div>
                    <div class="flex flex-wrap items-end justify-between gap-6 mt-4">
                        <div>
                            <h2 class="section-title reveal">Deception network.<br>Live telemetry. Risk scoring.</h2>
                        </div>
                        <div class="flex items-center gap-3 reveal">
                            <form action="/api/simulate/step" method="post">
                                <input type="hidden" name="key" value="{{E(operatorApiKey)}}">
                                <button class="btn btn-ghost" type="submit">Trigger Step</button>
                            </form>
                            <form action="/api/reset" method="post">
                                <input type="hidden" name="key" value="{{E(operatorApiKey)}}">
                                <button class="btn btn-ghost" type="submit">Reset</button>
                            </form>
                            <button hx-get="/api/canaries/modal" hx-target="#modal-container" hx-swap="innerHTML" class="btn btn-primary">Deploy Canary</button>
                        </div>
                    </div>
                </div>

                <!-- Metrics -->
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8 reveal">
                    {{RenderMetric("Active Canaries", totalCanaries.ToString(), "Deployed assets", "shield", "metric-canaries")}}
                    {{RenderMetric("Triggered", triggeredCanaries.ToString(), "Attacker touches", "target", "metric-triggered")}}
                    {{RenderMetric("Exfil Attempts", exfilAttempts.ToString(), "Fake data accessed", "database", "metric-exfil")}}
                    {{RenderMetric("Automation", automationText, "Tool profiling", "cpu", "metric-automation")}}
                </div>

                <!-- Graph + Profile -->
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 reveal">
                    <div class="lg:col-span-2 space-y-6">
                        <div class="panel p-6">
                            <div class="flex justify-between items-center mb-5">
                                <h3 class="font-semibold text-lg">Attack Graph</h3>
                                <button onclick="reloadGraph()" class="text-xs text-teal-400 hover:text-teal-300 font-medium transition-colors">Refresh</button>
                            </div>
                            <div id="vis-graph" class="h-[420px] w-full rounded-xl bg-black/50 border border-white/5"></div>
                        </div>
                        <div class="panel p-6">
                            <div class="flex justify-between items-center mb-5">
                                <div>
                                    <h3 class="font-semibold text-lg">Canary Registry</h3>
                                    <p class="text-xs text-zinc-500 mt-1">Monitored deception assets deployed in environment</p>
                                </div>
                            </div>
                            <div id="canary-list-container">
                                {{RenderCanaryTablePartial(canaries)}}
                            </div>
                        </div>
                    </div>

                    <div class="space-y-6">
                        <div class="panel p-6">
                            <div class="flex items-start justify-between mb-6">
                                <div>
                                    <h3 class="font-semibold text-lg">Attacker Profile</h3>
                                    <div id="profile-attacker-ip" class="text-xs text-zinc-500 mt-1 mono">{{E(attackerIp)}}</div>
                                </div>
                                <div id="profile-risk-ring" class="risk-ring" style="background: conic-gradient(#fb7185 calc({{riskScore}} * 1%), rgba(255,255,255,0.08) 0);"><div class="risk-ring-inner"><span id="profile-risk-score" class="mono text-sm font-bold">{{riskScore}}</span></div></div>
                            </div>
                            <div class="space-y-3 mb-6">
                                {{RenderProfileRow("Risk Level", riskLevel, "profile-risk-level")}}
                                {{RenderProfileRow("Chain Depth", $"Level {chainDepth}", "profile-chain-depth")}}
                                {{RenderProfileRow("Data Served", $"{exfilAttempts} lures", "profile-exfil-lures")}}
                                {{RenderProfileRow("Workspace", snapshot.Workspace.Name)}}
                            </div>
                            <div class="bg-rose-500/10 border border-rose-500/20 rounded-xl p-4">
                                <div class="text-[10px] font-bold uppercase tracking-wider text-rose-400 mb-2">Intelligence Summary</div>
                                <div id="profile-summary" class="text-sm text-zinc-300 leading-relaxed">{{E(summary)}}</div>
                            </div>
                            <button hx-get="/api/attacker/details" hx-target="#modal-container" hx-swap="innerHTML" class="w-full mt-4 py-2.5 px-4 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-xs font-bold text-rose-200 transition-colors flex items-center justify-center gap-2">
                                <svg class="w-4 h-4 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
                                View Forensic Dossier
                            </button>
                        </div>
                        <div class="panel p-6 flex flex-col" style="height:420px">
                            <div class="flex items-center justify-between mb-4">
                                <h3 class="font-semibold text-lg">Live Telemetry</h3>
                                <span class="relative flex h-2.5 w-2.5">
                                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                                    <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
                                </span>
                            </div>
                            <div hx-ext="sse" sse-connect="/api/events/stream?key={{E(Uri.EscapeDataString(operatorApiKey))}}" sse-swap="message" hx-swap="afterbegin" id="live-events-container" class="flex-1 overflow-y-auto space-y-3 pr-2">
                                {{RenderLiveEventsFeedPartial(events)}}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <div class="gradient-line"></div>

        <!-- ARCHITECTURE -->
        <section id="architecture" class="py-24">
            <div class="shell">
                <div class="text-center mb-16">
                    <div class="section-label justify-center reveal">
                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>
                        Engineering
                    </div>
                    <h2 class="section-title mt-5 reveal">Production-grade from<br>day one.</h2>
                    <p class="section-desc mx-auto mt-6 reveal">Architected as a high-performance active deception engine powered by .NET 9, HTMX, EF Core, Prometheus, Terraform, and Docker.</p>
                </div>
                <div class="grid md:grid-cols-2 lg:grid-cols-4 gap-5">
                    <div class="feature-card stagger-item">
                        <div class="mono text-xs text-teal-400 font-bold mb-3">.NET 9 MINIMAL APIS</div>
                        <p class="text-sm text-zinc-500 leading-relaxed">Typed C# endpoints for canary CRUD, shadow interceptors, Prometheus metrics, and simulation flows.</p>
                    </div>
                    <div class="feature-card stagger-item">
                        <div class="mono text-xs text-amber-400 font-bold mb-3">HTMX + SSE</div>
                        <p class="text-sm text-zinc-500 leading-relaxed">Server-rendered UI with live telemetry streaming and modal interactions without SPA build complexity.</p>
                    </div>
                    <div class="feature-card stagger-item">
                        <div class="mono text-xs text-violet-400 font-bold mb-3">EF CORE + DUAL DB</div>
                        <p class="text-sm text-zinc-500 leading-relaxed">SQLite for zero-config local dev. PostgreSQL auto-selected when deployed with Docker Compose.</p>
                    </div>
                    <div class="feature-card stagger-item">
                        <div class="mono text-xs text-rose-400 font-bold mb-3">GROQ LLM + PROFILING</div>
                        <p class="text-sm text-zinc-500 leading-relaxed">Llama 3.3 70B generates contextual decoys and threat summaries. Behavioral profiler scores every session.</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- FOOTER -->
        <footer class="border-t border-white/5 py-8">
            <div class="shell flex flex-wrap items-center justify-between gap-4 text-xs text-zinc-600">
                <div class="flex items-center gap-2">
                    <svg class="w-4 h-4 text-teal-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                    ShadowLure &mdash; Active Deception Platform
                </div>
                <div class="mono">workspace: {{E(snapshot.Workspace.ApiKey)}}</div>
            </div>
        </footer>

        <div id="modal-container"></div>

        <script>
            // Every read endpoint requires the operator key too (see RequireOperatorKeyAsync
            // in Program.cs). This page only rendered because the request that loaded it
            // already carried a valid key, so it's safe to reuse here for this page's own
            // background fetch/SSE calls - EventSource can't set custom headers, so the SSE
            // connection carries it as a query param instead of a header.
            const OPERATOR_KEY = "{{EncodeForJsStringLiteral(operatorApiKey)}}";

            /* Lenis Smooth Scroll */
            const lenis = new Lenis({
                duration: 1.2,
                easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
                smooth: true
            });
            function raf(time) {
                lenis.raf(time);
                requestAnimationFrame(raf);
            }
            requestAnimationFrame(raf);

            /* GSAP ScrollTrigger */
            gsap.registerPlugin(ScrollTrigger);

            // Hero reveals
            gsap.utils.toArray('.hero .reveal').forEach((el, i) => {
                gsap.fromTo(el, { opacity: 0, y: 50 }, { opacity: 1, y: 0, duration: 1, delay: 0.15 * i, ease: 'power3.out' });
            });

            // Section reveals
            gsap.utils.toArray('section:not(.hero) .reveal').forEach(el => {
                gsap.fromTo(el, { opacity: 0, y: 40 }, {
                    opacity: 1, y: 0, duration: 0.9, ease: 'power3.out',
                    scrollTrigger: { trigger: el, start: 'top 85%', toggleActions: 'play none none none' }
                });
            });

            // Stagger cards
            document.querySelectorAll('.stagger-item').forEach((el, i) => {
                const section = el.closest('section');
                gsap.fromTo(el, { opacity: 0, y: 30 }, {
                    opacity: 1, y: 0, duration: 0.7, delay: i % 4 * 0.12, ease: 'power2.out',
                    scrollTrigger: { trigger: section, start: 'top 70%', toggleActions: 'play none none none' }
                });
            });

            // Parallax glows
            gsap.to('.hero-glow-1', { y: -80, scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: 1 } });
            gsap.to('.hero-glow-2', { y: 60, scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: 1 } });

            /* Vis.js Graph */
            let network = null;
            function reloadGraph() {
                fetch('/api/graph/data', { headers: { 'X-Operator-Key': OPERATOR_KEY } })
                    .then(res => res.json())
                    .then(data => {
                        const container = document.getElementById('vis-graph');
                        if (!container) return;
                        const options = {
                            physics: {
                                enabled: true,
                                solver: 'barnesHut',
                                barnesHut: {
                                    gravitationalConstant: -3800,
                                    centralGravity: 0.015,
                                    springLength: 210,
                                    springConstant: 0.03,
                                    damping: 0.35,
                                    avoidOverlap: 1
                                },
                                stabilization: { iterations: 120 }
                            },
                            interaction: { hover: true, dragNodes: true, zoomView: true, dragView: true },
                            nodes: {
                                shape: 'ellipse',
                                borderWidth: 2,
                                margin: { top: 14, bottom: 14, left: 20, right: 20 },
                                // vis-network's font.bold/ital/mono sub-config only applies when
                                // `multi` markdown parsing is enabled on the label text (it isn't
                                // here); passing bold:true against a plain font config is invalid
                                // per vis-network's own options validator and does nothing visually,
                                // so it's simply omitted rather than "fixed" to a no-op value.
                                font: { color: '#ffffff', face: 'Inter', size: 12 },
                                shadow: { enabled: true, color: 'rgba(0,0,0,0.6)', size: 10 }
                            },
                            edges: {
                                width: 2.5,
                                smooth: { type: 'curvedCW', roundness: 0.35 },
                                font: { color: '#fbbf24', size: 11, face: 'JetBrains Mono', background: '#09090b', strokeWidth: 4, strokeColor: '#09090b', align: 'horizontal' },
                                arrows: { to: { enabled: true, scaleFactor: 1.2 } }
                            }
                        };
                        network = new vis.Network(container, data, options);
                    });
            }
            function updateCockpitStats() {
                fetch('/api/cockpit/stats', { headers: { 'X-Operator-Key': OPERATOR_KEY } })
                    .then(res => res.json())
                    .then(data => {
                        const triggeredEl = document.getElementById('metric-triggered');
                        if (triggeredEl) triggeredEl.innerText = data.triggered;

                        const exfilEl = document.getElementById('metric-exfil');
                        if (exfilEl) exfilEl.innerText = data.exfil;

                        const autoEl = document.getElementById('metric-automation');
                        if (autoEl) autoEl.innerText = data.automation;

                        const scoreEl = document.getElementById('profile-risk-score');
                        if (scoreEl) scoreEl.innerText = data.riskScore;

                        const ringEl = document.getElementById('profile-risk-ring');
                        if (ringEl) ringEl.style.background = `conic-gradient(#fb7185 ${data.riskScore}%, rgba(255,255,255,0.08) 0)`;

                        const levelEl = document.getElementById('profile-risk-level');
                        if (levelEl) levelEl.innerText = data.riskLevel;

                        const depthEl = document.getElementById('profile-chain-depth');
                        if (depthEl) depthEl.innerText = `Level ${data.chainDepth}`;

                        const exfilLuresEl = document.getElementById('profile-exfil-lures');
                        if (exfilLuresEl) exfilLuresEl.innerText = `${data.exfil} lures`;

                        const ipEl = document.getElementById('profile-attacker-ip');
                        if (ipEl) ipEl.innerText = data.attackerIp;

                        const summaryEl = document.getElementById('profile-summary');
                        if (summaryEl) summaryEl.innerText = data.summary;

                        if (data.tableHtml) {
                            const canaryList = document.getElementById('canary-list-container');
                            if (canaryList) canaryList.innerHTML = data.tableHtml;
                        }
                    });
            }

            document.body.addEventListener("htmx:sseMessage", (event) => {
                setTimeout(reloadGraph, 200);
                setTimeout(updateCockpitStats, 300);
            });

            document.addEventListener("DOMContentLoaded", reloadGraph);
            document.body.addEventListener("htmx:afterSwap", (event) => {
                if (event.target.id === "canary-list-container") {
                    setTimeout(reloadGraph, 250);
                }
            });

            /* Smooth anchor scrolling with Lenis */
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function(e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) lenis.scrollTo(target, { offset: -60 });
                });
            });
        </script>
    </html>
    """;
}


string RenderMetric(string label, string value, string note, string icon = "shield", string valueId = "")
{
    var svg = icon switch {
        "shield" => """<svg class="w-5 h-5 text-teal-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>""",
        "target" => """<svg class="w-5 h-5 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>""",
        "database" => """<svg class="w-5 h-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"/></svg>""",
        "cpu" => """<svg class="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg>""",
        _ => ""
    };

    var idAttr = string.IsNullOrWhiteSpace(valueId) ? "" : $"id=\"{valueId}\" ";

    return $"""
    <div class="panel p-5 flex items-start gap-4">
        <div class="p-2.5 rounded-lg bg-white/5 border border-white/5">
            {svg}
        </div>
        <div>
            <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider">{E(label)}</div>
            <div {idAttr}class="mt-1 text-2xl font-bold mono">{E(value)}</div>
            <div class="mt-1 text-xs text-slate-500">{E(note)}</div>
        </div>
    </div>
    """;
}

string RenderProfileRow(string label, string value, string valueId = "")
{
    var idAttr = string.IsNullOrWhiteSpace(valueId) ? "" : $"id=\"{valueId}\" ";
    return $"""
    <div class="flex items-center justify-between py-2 border-b border-white/5">
        <span class="text-xs text-slate-400">{E(label)}</span>
        <span {idAttr}class="text-sm font-medium text-slate-200 mono">{E(value)}</span>
    </div>
    """;
}

string RenderCanaryTablePartial(List<CanaryToken> canaries)
{
    if (canaries.Count == 0)
    {
        return """
        <div class="text-center p-8 border border-dashed border-white/10 rounded-lg bg-white/5">
            <h4 class="text-sm font-semibold text-slate-200">No canaries deployed</h4>
            <p class="mt-1 text-xs text-slate-400">Deploy a decoy credential to start monitoring.</p>
            <button hx-get="/api/canaries/modal" hx-target="#modal-container" hx-swap="innerHTML" class="btn btn-secondary text-xs mt-4">Deploy Canary</button>
        </div>
        """;
    }

    var rows = new StringBuilder();
    foreach (var c in canaries)
    {
        var statusColor = c.Status == TokenStatus.Triggered ? "text-rose-400 bg-rose-400/10 border-rose-400/20" : "text-teal-400 bg-teal-400/10 border-teal-400/20";

        rows.Append($"""
        <tr class="border-b border-white/5 group hover:bg-white/5 transition-colors">
            <td class="py-3 px-4">
                <div class="font-medium text-sm text-slate-200">{E(c.Name)}</div>
                <div class="text-xs text-slate-500 mt-0.5">{E(c.ContextInfo)}</div>
            </td>
            <td class="py-3 px-4 text-xs text-amber-300 mono">{E(HumanizeTokenType(c.Type))}</td>
            <td class="py-3 px-4 text-xs text-slate-400 mono max-w-[200px] truncate">{E(c.DecoyValue)}</td>
            <td class="py-3 px-4">
                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border {statusColor} uppercase tracking-wider">
                    {E(c.Status.ToString())}
                </span>
            </td>
            <td class="py-3 px-4 text-right space-x-2">
                <button hx-get="/api/canaries/{c.Id}/details" hx-target="#modal-container" hx-swap="innerHTML" class="text-xs text-slate-400 hover:text-teal-400 transition-colors">Inspect</button>
                <button hx-delete="/api/canaries/{c.Id}" hx-target="#canary-list-container" hx-swap="innerHTML" class="text-xs text-slate-400 hover:text-rose-400 transition-colors">Revoke</button>
            </td>
        </tr>
        """);
    }

    return $"""
    <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
            <thead>
                <tr class="border-b border-white/10 text-xs font-semibold text-slate-400 uppercase tracking-wider bg-white/5">
                    <th class="py-2.5 px-4 font-medium">Asset</th>
                    <th class="py-2.5 px-4 font-medium">Type</th>
                    <th class="py-2.5 px-4 font-medium">Payload</th>
                    <th class="py-2.5 px-4 font-medium">Status</th>
                    <th class="py-2.5 px-4 font-medium text-right">Actions</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
    """;
}

string RenderLiveEventsFeedPartial(List<TriggerEvent> events)
{
    if (events.Count == 0)
    {
        return """
        <div class="rounded-md border border-slate-800 bg-black/30 p-6 text-center">
            <div class="mono text-sm font-bold text-slate-200">Deception network listening</div>
            <p class="mt-2 text-sm text-slate-500">Trigger the scenario to capture the first attacker touch.</p>
        </div>
        """;
    }

    var html = new StringBuilder();
    foreach (var e in events)
    {
        html.Append(RenderEventCard(e));
    }
    return html.ToString();
}

string RenderEventCard(TriggerEvent e, bool compact = false)
{
    var pulse = compact ? "animate-pulse " : "";
    return $"""
    <div class="{pulse}p-3 rounded-lg bg-white/5 border border-white/10 hover:border-rose-500/30 transition-colors group">
        <div class="flex justify-between items-start mb-2">
            <div class="flex items-center gap-2">
                <span class="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                <span class="text-xs font-semibold text-slate-200 mono">{E(e.SimulatedTool)}</span>
            </div>
            <span class="text-[10px] text-slate-500 mono">{E(e.TriggeredAt.ToLocalTime().ToString("HH:mm:ss"))}</span>
        </div>
        <div class="text-xs text-slate-300 mb-1">Target: <span class="text-teal-400 font-medium">{E(e.CanaryToken?.Name ?? "Shadow asset")}</span></div>
        <div class="text-[11px] text-slate-400 mono truncate p-1.5 bg-black/40 rounded border border-white/5">{E(e.RequestPayload)}</div>
        <div class="flex justify-between items-center mt-2 pt-2 border-t border-white/5 text-[10px] text-slate-500 uppercase tracking-wider">
            <span>Depth {e.ChainDepth}</span>
            <span class="mono text-amber-200/70">{E(e.AttackerIp)}</span>
        </div>
    </div>
    """;
}

string RenderCreateCanaryModalPartial()
{
    return """
    <div class="fixed inset-0 z-50 grid place-items-center bg-black/80 p-4 backdrop-blur-md">
        <div class="w-full max-w-xl rounded-lg border border-teal-300/30 bg-[#071011] p-6 shadow-2xl">
            <div class="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                    <h3 class="text-xl font-black text-white">Deploy contextual canary</h3>
                    <p class="mt-1 text-sm text-slate-400">Generate a decoy that fits the environment and links into the active deception path.</p>
                </div>
                <button onclick="document.getElementById('modal-container').innerHTML=''" class="rounded-md border border-slate-700 px-3 py-1 text-sm font-bold text-slate-300">Close</button>
            </div>

            <form hx-post="/api/canaries" hx-target="#canary-list-container" hx-swap="innerHTML" class="mt-5 space-y-4">
                <label class="block">
                    <span class="mono text-xs font-bold uppercase text-slate-400">Target environment</span>
                    <input type="text" name="techStack" placeholder="AcmeCorp - AWS S3, PostgreSQL, Kubernetes" required class="mt-2 w-full rounded-md border border-slate-700 bg-black/40 p-3 text-sm text-slate-100 outline-none focus:border-teal-300">
                </label>

                <label class="block">
                    <span class="mono text-xs font-bold uppercase text-slate-400">Decoy name</span>
                    <input type="text" name="name" placeholder="prod-s3-replication-key" class="mt-2 w-full rounded-md border border-slate-700 bg-black/40 p-3 text-sm text-slate-100 outline-none focus:border-teal-300">
                </label>

                <label class="block">
                    <span class="mono text-xs font-bold uppercase text-slate-400">Service type</span>
                    <select name="type" class="mt-2 w-full rounded-md border border-slate-700 bg-black/40 p-3 text-sm text-slate-100 outline-none focus:border-teal-300">
                        <option value="AwsKey">AWS key / S3 interceptor</option>
                        <option value="DbConnection">PostgreSQL connection</option>
                        <option value="K8sSecret">Kubernetes secret</option>
                        <option value="ApiKey">Internal API token</option>
                    </select>
                </label>

                <div class="flex justify-end gap-3 pt-2">
                    <button type="button" onclick="document.getElementById('modal-container').innerHTML=''" class="button">Cancel</button>
                    <button type="submit" onclick="setTimeout(() => { document.getElementById('modal-container').innerHTML=''; reloadGraph(); }, 650)" class="button button-hot">Generate decoy</button>
                </div>
            </form>
        </div>
    </div>
    """;
}

string RenderCanaryDetailsModalPartial(CanaryToken canary)
{
    var links = new StringBuilder();
    foreach (var link in canary.OutgoingLinks)
    {
        links.Append($"""
        <li class="rounded-md border border-slate-800 bg-black/30 p-3">
            <div class="text-sm font-bold text-amber-100">{E(link.TargetCanary?.Name ?? "Linked canary")}</div>
            <div class="mt-1 mono text-xs text-slate-400">{E(link.BreadcrumbLocation)}</div>
        </li>
        """);
    }

    var route = ShadowRouteFor(canary.Type);
    return $$"""
    <div class="fixed inset-0 z-50 grid place-items-center bg-black/80 p-4 backdrop-blur-md">
        <div class="w-full max-w-2xl rounded-lg border border-teal-300/30 bg-[#071011] p-6 shadow-2xl">
            <div class="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                    <h3 class="text-xl font-black text-white">{{E(canary.Name)}}</h3>
                    <p class="mt-1 text-sm text-slate-400">{{E(HumanizeTokenType(canary.Type))}} deception asset</p>
                </div>
                <button onclick="document.getElementById('modal-container').innerHTML=''" class="rounded-md border border-slate-700 px-3 py-1 text-sm font-bold text-slate-300">Close</button>
            </div>

            <div class="mt-5 space-y-4">
                <div>
                    <div class="mono text-xs font-bold uppercase text-slate-500">Credential payload</div>
                    <div class="mt-2 break-all rounded-md border border-slate-800 bg-black/40 p-3 mono text-sm text-amber-100">{{E(canary.DecoyValue)}}</div>
                </div>

                <div>
                    <div class="mono text-xs font-bold uppercase text-slate-500">Breadcrumbs</div>
                    <ul class="mt-2 space-y-2">{{(links.Length > 0 ? links.ToString() : "<li class=\"text-sm text-slate-500\">No outgoing breadcrumbs configured.</li>")}}</ul>
                </div>

                <div>
                    <div class="mono text-xs font-bold uppercase text-slate-500">Windows PowerShell Test Command (curl.exe)</div>
                    <pre class="mt-2 overflow-x-auto rounded-md border border-slate-800 bg-black/50 p-3 mono text-xs text-teal-100">curl.exe -X POST http://localhost:5246/api/shadow/{{route}}/{{canary.Id}} -H "User-Agent: {{E(DefaultUserAgentFor(canary.Type))}}" -d "{{E(DefaultPayloadFor(canary.Type))}}"</pre>
                </div>

                <div class="mt-3">
                    <div class="mono text-xs font-bold uppercase text-slate-500">Native PowerShell Command (Invoke-RestMethod)</div>
                    <pre class="mt-2 overflow-x-auto rounded-md border border-slate-800 bg-black/50 p-3 mono text-xs text-amber-100">Invoke-RestMethod -Uri "http://localhost:5246/api/shadow/{{route}}/{{canary.Id}}" -Method POST -Headers @{ "User-Agent" = "{{E(DefaultUserAgentFor(canary.Type))}}" } -Body "{{E(DefaultPayloadFor(canary.Type))}}"</pre>
                </div>
            </div>
        </div>
    </div>
    """;
}

string RenderAttackerDossierModalPartial(AttackerSession? session)
{
    if (session == null)
    {
        return """
        <div class="fixed inset-0 z-50 grid place-items-center bg-black/80 p-4 backdrop-blur-md">
            <div class="w-full max-w-lg rounded-xl border border-slate-800 bg-[#071011] p-6 shadow-2xl text-center">
                <h3 class="text-lg font-bold text-white">No Attacker Session Captured</h3>
                <p class="mt-2 text-sm text-slate-400">Trigger a canary token to capture full forensic attacker telemetry.</p>
                <button onclick="document.getElementById('modal-container').innerHTML=''" class="mt-5 rounded-md border border-slate-700 px-4 py-2 text-xs font-bold text-slate-300">Close</button>
            </div>
        </div>
        """;
    }

    var riskColor = session.RiskScore switch {
        >= 80 => "bg-rose-500/20 text-rose-400 border-rose-500/30",
        >= 40 => "bg-amber-500/20 text-amber-400 border-amber-500/30",
        _ => "bg-teal-500/20 text-teal-400 border-teal-500/30"
    };

    var timelineRows = new StringBuilder();
    foreach (var ev in session.Events.OrderByDescending(e => e.TriggeredAt))
    {
        timelineRows.Append($"""
        <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
            <td class="py-3 px-3 text-xs text-slate-400 mono whitespace-nowrap">{E(ev.TriggeredAt.ToLocalTime().ToString("HH:mm:ss"))}</td>
            <td class="py-3 px-3 text-xs font-bold text-slate-200 mono whitespace-nowrap">{E(ev.SimulatedTool)}</td>
            <td class="py-3 px-3 text-xs text-teal-400 font-medium whitespace-nowrap">{E(ev.CanaryToken?.Name ?? "Shadow asset")}</td>
            <td class="py-3 px-3 text-xs text-slate-300 mono whitespace-pre-wrap break-all max-w-[320px] bg-black/30 rounded p-2 border border-white/5">{E(ev.RequestPayload)}</td>
            <td class="py-3 px-3 text-xs text-amber-200/90 mono whitespace-pre-wrap break-all max-w-[380px] bg-black/40 rounded p-2 border border-white/5">{E(ev.ResponsePayload)}</td>
        </tr>
        """);
    }

    return $$"""
    <div class="fixed inset-0 z-50 grid place-items-center bg-black/80 p-4 backdrop-blur-md overflow-y-auto">
        <div class="w-full max-w-5xl rounded-2xl border border-rose-500/30 bg-[#080a0f] p-6 shadow-2xl space-y-6 my-8">
            <!-- Modal Header -->
            <div class="flex items-start justify-between border-b border-white/10 pb-4">
                <div>
                    <div class="flex items-center gap-3">
                        <span class="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse"></span>
                        <h3 class="text-xl font-extrabold text-white tracking-tight">Attacker Forensic Dossier</h3>
                        <span class="px-2.5 py-0.5 rounded-full text-xs font-bold border {{riskColor}} uppercase tracking-wider">
                            {{session.RiskLevel}} RISK ({{session.RiskScore}}/100)
                        </span>
                    </div>
                    <p class="mt-1 text-xs text-slate-400 mono">Session Fingerprint: {{E(session.Fingerprint[..Math.Min(16, session.Fingerprint.Length)])}}... | First Seen: {{E(session.FirstSeen.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"))}}</p>
                </div>
                <button onclick="document.getElementById('modal-container').innerHTML=''" class="rounded-lg border border-white/10 bg-white/5 px-3.5 py-1.5 text-xs font-bold text-slate-300 hover:bg-white/10 transition-colors">Close</button>
            </div>

            <!-- Attacker Overview Cards -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                    <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Attacker IP</div>
                    <div class="mt-1 text-sm font-bold text-amber-300 mono">{{E(session.AttackerIp)}}</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">{{(session.AttackerIp == "127.0.0.1" || session.AttackerIp == "::1" ? "Localhost Connection" : "Remote Network Connection")}}</div>
                </div>

                <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                    <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">User Agent / Client</div>
                    <div class="mt-1 text-xs font-bold text-slate-200 mono truncate" title="{{E(session.UserAgent)}}">{{E(session.UserAgent)}}</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">CLI Security Tooling</div>
                </div>

                <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                    <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Automation Profile</div>
                    <div class="mt-1 text-xs font-bold text-teal-300 mono">{{(session.AutomationDetected ? "Automated Tooling" : "Interactive Shell")}}</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">Behavioral Profiler</div>
                </div>

                <div class="p-3.5 rounded-xl bg-white/5 border border-white/10">
                    <div class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Max Chain Depth</div>
                    <div class="mt-1 text-sm font-bold text-rose-400 mono">Level {{session.MaxChainDepth}}</div>
                    <div class="text-[10px] text-slate-500 mt-0.5">{{session.Events.Count}} Decoy Interceptions</div>
                </div>
            </div>

            <!-- Threat Intel Summary -->
            <div class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20">
                <div class="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-rose-400 mb-2">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    AI Threat Intelligence Behavioral Profile
                </div>
                <p class="text-sm text-slate-200 leading-relaxed font-sans">{{E(session.LlmProfileSummary)}}</p>
            </div>

            <!-- Event Chronology Trace Table -->
            <div>
                <div class="flex items-center justify-between mb-3">
                    <h4 class="text-sm font-bold text-slate-200">Execution Chronology Trace ({{session.Events.Count}} Events)</h4>
                    <span class="text-xs text-slate-500 mono">Real-time HTTP Request/Response Logs</span>
                </div>
                <div class="overflow-x-auto rounded-xl border border-white/10 bg-black/40">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="border-b border-white/10 text-[10px] font-semibold text-slate-400 uppercase tracking-wider bg-white/5">
                                <th class="py-2.5 px-3">Time</th>
                                <th class="py-2.5 px-3">Tool</th>
                                <th class="py-2.5 px-3">Canary Target</th>
                                <th class="py-2.5 px-3">Attacker Request</th>
                                <th class="py-2.5 px-3">Deception Response</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{(timelineRows.Length > 0 ? timelineRows.ToString() : "<tr><td colspan=\"5\" class=\"py-4 text-center text-xs text-slate-500\">No events recorded for this session.</td></tr>")}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    """;
}

string BuildCanaryName(string techStack, TokenType tokenType)
{
    var company = string.IsNullOrWhiteSpace(techStack)
        ? "acme"
        : techStack.Split(new[] { ' ', ',', '-' }, StringSplitOptions.RemoveEmptyEntries)[0].ToLowerInvariant();
    var suffix = tokenType switch
    {
        TokenType.AwsKey => "prod-s3-key",
        TokenType.DbConnection => "ledger-db-readonly",
        TokenType.K8sSecret => "eks-service-secret",
        _ => "internal-api-token"
    };

    return $"{company}-{suffix}-{Random.Shared.Next(100, 999)}";
}

string BuildBreadcrumb(CanaryToken token)
{
    return token.Type switch
    {
        TokenType.AwsKey => $"s3://{token.Name}/terraform.tfstate",
        TokenType.DbConnection => $"postgresql://{token.Name}.internal:5432/customers",
        TokenType.K8sSecret => $"k8s://payments/prod/{token.Name}",
        _ => $"https://internal-api.local/tokens/{token.Name}"
    };
}

string HumanizeTokenType(TokenType tokenType)
{
    return tokenType switch
    {
        TokenType.AwsKey => "AWS S3",
        TokenType.DbConnection => "PostgreSQL",
        TokenType.K8sSecret => "Kubernetes",
        _ => "Internal API"
    };
}

string ShadowRouteFor(TokenType tokenType)
{
    return tokenType switch
    {
        TokenType.AwsKey => "aws",
        TokenType.DbConnection => "db",
        TokenType.K8sSecret => "k8s",
        _ => "api"
    };
}

string DefaultUserAgentFor(TokenType tokenType)
{
    return tokenType switch
    {
        TokenType.AwsKey => "aws-cli/2.15.10",
        TokenType.DbConnection => "psql (PostgreSQL) 16.1",
        TokenType.K8sSecret => "kubectl/v1.30",
        _ => "python-requests/2.32"
    };
}

string DefaultPayloadFor(TokenType tokenType)
{
    return tokenType switch
    {
        TokenType.AwsKey => "aws s3 ls --recursive",
        TokenType.DbConnection => "SELECT * FROM customers LIMIT 100;",
        TokenType.K8sSecret => "kubectl get secrets -A -o yaml",
        _ => "GET /v1/internal/invoices?tenant=enterprise"
    };
}

string E(string? value)
{
    return WebUtility.HtmlEncode(value ?? string.Empty);
}

// Embeds a value inside the JSON object literal of a single-quoted HTML
// attribute (htmx's hx-headers='{"...": "..."}' pattern). Escapes backslashes
// and double-quotes so the result stays valid JSON, then HTML-escapes any
// apostrophe so it can't break out of the attribute's single-quote delimiter.
string EncodeForSingleQuotedJsonAttribute(string value)
{
    var jsonEscaped = value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    return jsonEscaped.Replace("'", "&#39;");
}

// Embeds a value inside a double-quoted JS string literal in an inline <script>
// block. Escapes backslash/double-quote for JS string validity, and breaks up
// any "</script" sequence so the value can never prematurely close the tag.
string EncodeForJsStringLiteral(string value)
{
    return value
        .Replace("\\", "\\\\")
        .Replace("\"", "\\\"")
        .Replace("</script", "<\\/script", StringComparison.OrdinalIgnoreCase);
}

record DashboardSnapshot(
    Workspace Workspace,
    List<CanaryToken> Canaries,
    List<CanaryLink> Links,
    List<TriggerEvent> Events,
    AttackerSession? Session);
