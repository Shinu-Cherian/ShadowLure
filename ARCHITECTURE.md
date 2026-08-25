# ShadowLure Technical Architecture & Engineering Design Document

This document provides a deep-dive architectural analysis of ShadowLure, explaining core design decisions, system components, trade-offs, scope boundaries, and the future engineering roadmap.

---

## 1. High-Level Architectural Rationale

### Why Minimal APIs over ASP.NET Core MVC / Controllers?

ShadowLure is designed to run as a high-throughput, low-latency security deception sidecar or standalone honeytrap node. Minimal APIs were selected for the primary HTTP entry point (`ShadowLure.Api`) due to several critical performance and engineering advantages:

1. Throughput & Latency: Minimal APIs eliminate controller action discovery overhead, model binding reflection pipelines, and filter stack execution, yielding lower allocation overhead per HTTP request.
2. Low Memory Footprint: A running ShadowLure instance executes within ~12MB of RAM, making it suitable for lightweight edge sidecar deployment alongside existing microservices.
3. HTMX Fragment Compatibility: Raw string interpolation and HTML partial rendering fit naturally into endpoint lambda expressions without requiring full Razor compilation pipelines.

---

## 2. Solution Layer Boundaries

The codebase enforces strict directional dependencies across five separate project layers:

```
[ ShadowLure.Api ]
       |
       +---> [ ShadowLure.Shadow ] ------+
       |                                 |
       +---> [ ShadowLure.Profiling ] ---+---> [ ShadowLure.Core ]
       |                                 |
       +---> [ ShadowLure.Infrastructure]+
```

- ShadowLure.Core: Zero-dependency domain model library defining entities (`CanaryToken`, `AttackerSession`, `TriggerEvent`), enums (`TokenType`, `TokenStatus`), and core abstractions.
- ShadowLure.Shadow: Implements the active deception synthesis engine (`IShadowEngine`), generating believable synthetic S3 directory structures, SQL query dataset arrays, and Kubernetes YAML secret payloads.
- ShadowLure.Profiling: Houses the behavioral analytics pipeline (`IBehavioralProfiler`), generating client SHA-256 fingerprints, detecting automated CLI security tool signatures, calculating active chain depth, and computing threat risk scores.
- ShadowLure.Infrastructure: Handles data persistence via Entity Framework Core, Prometheus metrics exposition (`MetricsService`), LLM summary synthesis (`GroqLlmService`), and alert notifications (`AlertNotifierService`).
- ShadowLure.Api: Endpoint routing layer, Server-Sent Events (SSE) stream producer, and HTMX server-side rendering host.

---

## 3. Shadow Deception Engine: Scope & Implementation Details

### Synthetic Payload Generation vs. Low-Level Protocol Proxies

It is critical to distinguish what the current version of the Shadow Engine (`IShadowEngine`) does and does not implement:

- What it DOES:
  - Intercepts incoming HTTP requests directed to decoy endpoint GUIDs (`/api/shadow/{serviceType}/{tokenId}`).
  - Inspects request payloads and User-Agent headers to match expected tool profiles (`aws-cli`, `psql`, `kubectl`, `python-requests`).
  - Synthesizes contextually accurate responses (e.g., XML S3 bucket listings containing fake breadcrumb keys, CSV tabular data, YAML secret manifests).
  - Embeds directional breadcrumbs into responses to entice adversaries to pivot laterally into secondary decoys.

- Scope Limits & What it DOES NOT (Yet) Do:
  - AWS SigV4 Validation: The current AWS shadow endpoint simulates S3 REST responses over HTTP/HTTPS, but does not parse or validate low-level AWS HMAC-SHA256 SigV4 Authorization header signatures.
  - PostgreSQL Wire Protocol: Database lures operate over HTTP API wrappers rather than implementing a full TCP port 5432 PostgreSQL wire protocol proxy.
  - eBPF Kernel Hooks: Telemetry collection currently occurs at the application HTTP layer rather than via Linux eBPF socket tracing.

---

## 4. Behavioral Profiling & Risk Scoring Algorithm

Attacker risk is evaluated dynamically using a multi-factor scoring algorithm implemented in `CaptureShadowEventAsync`:

$$\text{Risk Score} = \min\Big(100, (\text{EventCount} \times 10) + (\text{MaxChainDepth} \times 25) + (\text{IsAutomation} \times 15) + (\text{ExfilAttempts} \times 50)\Big)$$

Threat Levels are mapped dynamically:
- Score < 30: Low Threat
- 30 <= Score < 60: Medium Threat
- 60 <= Score < 100: High Threat
- Score = 100: Critical Threat

Automation Detection: `BehavioralProfiler` analyzes HTTP User-Agent strings and request interval velocity to detect automated scanners (`aws-cli`, `kubectl`, `nmap`, `python-requests`) versus interactive human shell sessions.

---

## 5. Known Limitations & Engineering Roadmap

1. Reverse Proxy & Public IP Resolution:
   - Current logic checks `X-Forwarded-For`, `X-Real-IP`, and `RemoteIpAddress`. Behind complex multi-hop proxies or Cloudflare, `ForwardedHeadersMiddleware` must be explicitly configured in `Program.cs`.
2. Real AWS SigV4 Interceptor Proxy:
   - Planned extension: Implement a dedicated AWS SigV4 request parser to extract access key IDs directly from raw `Authorization: AWS4-HMAC-SHA256 Credential=AKIA...` headers.
3. Webhook Alert Rate-Limiting:
   - High-velocity automated scanner attacks can flood external Slack/webhook endpoints. A leaky-bucket rate limiter should be added to `AlertNotifierService`.
4. Multi-Region Distributed Honeynet:
   - Synchronize attacker sessions across distributed regional nodes via Redis Pub/Sub or gRPC stream backplanes.
