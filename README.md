# ShadowLure

[![CI](https://github.com/Shinu-Cherian/ShadowLure/actions/workflows/ci.yml/badge.svg)](https://github.com/Shinu-Cherian/ShadowLure/actions/workflows/ci.yml)
[![.NET 9](https://img.shields.io/badge/.NET-9.0-512BD4)](https://dotnet.microsoft.com/)

**Active deception platform for cloud credentials.** ShadowLure turns leaked AWS keys, database connection strings, Kubernetes secrets, and internal API tokens into instrumented decoys. When an attacker uses one, ShadowLure doesn't just log a hit and drop the connection — it serves a believable synthetic response, follows the attacker through a multi-hop chain of linked decoys, fingerprints their tooling, and scores the session's risk in real time.

---

## Why active deception

Static canary tokens fire a single binary alert and stop there. ShadowLure treats a triggered token as the *start* of an engagement, not the end of one:

- **Zero false positives.** Decoy credentials are never used by legitimate systems, so any traffic against one is high-confidence malicious activity by construction.
- **Multi-hop breadcrumb chains.** An AWS S3 decoy's response embeds a breadcrumb pointing at a database credential; that credential's response points at a Kubernetes secret; that secret points at an internal API token. Each hop the attacker follows deepens the forensic picture and raises the session's risk score.
- **Believable synthetic responses.** Instead of a generic 403 or a dropped connection, triggered endpoints return realistic S3 bucket listings, CSV exports, Kubernetes secret manifests, and JSON API payloads — engineered to keep an attacker interacting rather than immediately suspecting a trap.
- **Behavioral profiling, not just IP logging.** Every trigger is fingerprinted by IP + User-Agent, classified against known CLI tool signatures (`aws-cli`, `psql`, `kubectl`, `boto3`, scanners), and checked for automation based on request cadence.

---

## Architecture

```
                          [ Client / Operator Browser ]
                                        |
                         HTTP / SSE Stream (HTMX + Vis.js)
                                        |
                                        v
                       +---------------------------------+
                       |        ShadowLure.Api           |
                       | (Minimal APIs, Routing, SSE)    |
                       +---------------------------------+
                          /             |             \
                         v              v              v
         +--------------------+ +---------------+ +------------------------+
         | ShadowLure.Shadow  | |  ShadowLure.  | | ShadowLure.Profiling   |
         | (Deception Engine) | | Core (Domain) | | (Behavioral Analytics) |
         +--------------------+ +---------------+ +------------------------+
                         \              |              /
                          v             v             v
                       +---------------------------------+
                       |    ShadowLure.Infrastructure    |
                       | (EF Core, SQLite/Postgres, LLM,  |
                       |          Alerting)               |
                       +---------------------------------+
```

| Project | Responsibility |
|---|---|
| `ShadowLure.Core` | Zero-dependency domain model: `CanaryToken`, `AttackerSession`, `TriggerEvent`, `CanaryLink`, and the enums/interfaces everything else depends on. |
| `ShadowLure.Shadow` | `IShadowEngine` — synthesizes the fake S3 listings, CSV exports, and Kubernetes/API JSON responses served to attackers. |
| `ShadowLure.Profiling` | `IBehavioralProfiler` — SHA-256 client fingerprinting, CLI tool signature detection, automation heuristics, and the risk-scoring formula. |
| `ShadowLure.Infrastructure` | EF Core persistence (SQLite for local dev, PostgreSQL in production), Prometheus metrics, the Groq LLM client, and Slack/webhook alerting. |
| `ShadowLure.Api` | Minimal API host: shadow trap routes, the HTMX-rendered operator dashboard, and the SSE telemetry stream. |

A deeper write-up of design decisions, trade-offs, and the production-hardening pass this codebase went through is in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Technology stack

| Layer | Choice |
|---|---|
| Backend | C# / .NET 9 Minimal APIs, Kestrel |
| Persistence | EF Core 9 — SQLite locally, PostgreSQL in production (auto-selected from the connection string) |
| Frontend | HTMX 1.9 (server-rendered fragments + SSE swaps), Tailwind CSS via the Play CDN, Vis.js Network for the topology graph |
| Observability | Prometheus (`prometheus-net`), Serilog structured logging |
| LLM | Groq (`llama-3.3-70b-versatile`) for decoy generation and attacker-profile summaries, with deterministic fallback templates when no API key is configured |
| Infrastructure | Docker, Terraform (AWS ECS Fargate + ALB + ECR) |
| Testing | xUnit |

> The Tailwind CDN script is the in-browser **Play CDN**, not a compiled production build — a known, deliberate trade-off to keep the dashboard a single self-contained file with no frontend build step. Fine for this project's scope; would be swapped for a compiled Tailwind pipeline in a larger app.

---

## API reference

### Shadow trap endpoints (unauthenticated by design — this is the surface attackers are meant to reach)

| Method | Route | Behavior |
|---|---|---|
| `POST` | `/api/shadow/aws/{tokenId:guid}` | Returns a synthetic S3 bucket listing for the given token. |
| `POST` | `/api/shadow/db/{tokenId:guid}` | Returns a synthetic CSV export; flagged as a data-exfiltration attempt. |
| `POST` | `/api/shadow/k8s/{tokenId:guid}` | Returns a fake Kubernetes secret manifest. |
| `POST` | `/api/shadow/api/{tokenId:guid}` | Returns a fake internal API JSON payload. |

Every hit against these routes returns its decoy response immediately; capture, risk scoring, LLM summarization, and alerting all happen asynchronously afterward — see [ARCHITECTURE.md](ARCHITECTURE.md) for why response latency matters here.

### Operator endpoints — every one of these requires the operator key

The dashboard renders real captured attacker IPs, raw request/response payloads, and decoy credential values — not just the mutating actions — so every route below is gated by the same key, not only the ones that write data.

| Method | Route | Behavior |
|---|---|---|
| `GET` | `/` | Renders the operator dashboard. |
| `GET` | `/api/canaries/table` | Renders the canary registry table as an HTML fragment. |
| `GET` | `/api/canaries/modal` | Renders the "deploy canary" modal. |
| `GET` | `/api/canaries/{id}/details` | Renders the inspection modal with ready-to-run test commands for that token. |
| `POST` | `/api/canaries` | Provisions a new canary token and links it into the breadcrumb chain. |
| `DELETE` | `/api/canaries/{id}` | Revokes and deletes a canary token. |
| `GET` | `/api/graph/data` | Returns the Vis.js node/edge graph as JSON. |
| `GET` | `/api/cockpit/stats` | Returns live metrics, risk score, and profile state as JSON. |
| `GET` | `/api/attacker/details` | Renders the forensic attacker dossier modal — real attacker IP, User-Agent, and full raw request/response payloads. |
| `GET` | `/api/events/stream` | Server-Sent Events stream of new trigger events. |
| `POST` | `/api/simulate/step` | Advances the built-in demo by one simulated trigger. |
| `POST` | `/api/simulate/full` | Runs the full four-step demo chain. |
| `POST` | `/api/reset` | Clears all sessions/events/canaries and reseeds the workspace. |
| `GET` | `/metrics` | Prometheus scrape endpoint. Point your scrape job's `Authorization`/custom-header config at it, or keep it on an internal-only network path. |

The key is accepted three ways, checked in this order: an `X-Operator-Key` header, a `key` form field, or a `key` query parameter. The rendered dashboard carries it automatically once you've loaded the page with a valid key — its own links, background `fetch` calls, and the SSE connection all propagate it forward — so in practice you only ever type it once, in the URL. See [Configuration](#configuration).

---

## Getting started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- Git

### Run locally

```bash
git clone https://github.com/Shinu-Cherian/ShadowLure.git
cd ShadowLure
dotnet build ShadowLure.sln
dotnet run --project src/ShadowLure.Api/ShadowLure.Api.csproj --launch-profile http
```

On startup, the console logs the exact URL to open, including the key:

```
[INF] Dashboard: http://localhost:5246/?key=dev-local-operator-key
```

In `Development` this is a fixed, insecure local-only key (a warning is logged alongside it) — every read and write on the dashboard requires it, not just deploy/revoke/reset. In `Production`, `OPERATOR_API_KEY` must be set to a real secret or the app refuses to start.

### Run with Docker Compose

```bash
cp .env.example .env   # fill in POSTGRES_PASSWORD and OPERATOR_API_KEY
docker compose up --build
```

This builds the app image, starts a PostgreSQL container, and serves the app at `http://localhost:5000`. Compose fails fast if `POSTGRES_PASSWORD` or `OPERATOR_API_KEY` are missing from `.env` rather than falling back to a committed default.

### Configuration

| Variable | Required | Purpose |
|---|---|---|
| `ConnectionStrings__DefaultConnection` | No — defaults to local SQLite | Set to a `Host=...` PostgreSQL connection string to switch persistence backends. |
| `GROQ_API_KEY` | No | Enables LLM-generated decoys and attacker-profile summaries. Falls back to deterministic templates when unset. |
| `OPERATOR_API_KEY` | **Yes, in Production** | Authenticates every operator route in the table above — dashboard, forensic dossier, metrics, and the mutating actions. Shadow trap endpoints (`/api/shadow/*`) stay unauthenticated on purpose. Generate one with `openssl rand -hex 32`. |

---

## Testing

```bash
dotnet test ShadowLure.sln
```

xUnit test suite covering `ShadowEngine`'s synthetic response generation and `BehavioralProfiler`'s fingerprinting, tool-signature detection, and risk-scoring formula (including the 0–100 cap and level thresholds documented in [ARCHITECTURE.md](ARCHITECTURE.md)). CI runs the full build, test, and a Docker build verification on every push — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Deploying to AWS

Terraform in [`terraform/`](terraform/) provisions a VPC, ALB, ECS Fargate service, ECR repository, and CloudWatch logging. The task definition pulls its configuration from AWS Secrets Manager rather than plaintext environment variables, so three secrets must exist first:

```bash
cd terraform
terraform init
terraform plan \
  -var="db_connection_string_secret_arn=<arn>" \
  -var="groq_api_key_secret_arn=<arn>" \
  -var="operator_api_key_secret_arn=<arn>"
terraform apply
```

---

## Project structure

```
src/
  ShadowLure.Core/            domain models
  ShadowLure.Shadow/          decoy response generation
  ShadowLure.Profiling/       fingerprinting + risk scoring
  ShadowLure.Infrastructure/  EF Core, metrics, LLM client, alerting
  ShadowLure.Api/             Minimal API host + dashboard
tests/ShadowLure.Tests/       xUnit test suite
terraform/                    AWS ECS Fargate infrastructure
```

---

## Author

Shinu Cherian — [LinkedIn](https://www.linkedin.com/in/shinucherian90/)
