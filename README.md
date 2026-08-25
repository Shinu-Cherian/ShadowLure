# ShadowLure

Active Deception Architecture and Honeytoken Orchestration Engine

ShadowLure is an enterprise-grade active cyber defense platform designed to detect, track, and profile unauthorized network intruders. Unlike conventional passive honeypots or static canary tokens that issue a single binary alert, ShadowLure deploys dynamic, contextual deception chains across cloud infrastructure, database environments, Kubernetes clusters, and API gateways. When an adversary interacts with a seeded lure, ShadowLure traps the threat actor inside an instrumented decoy path, serving high-fidelity simulated responses while capturing real-time forensic telemetry, tool fingerprints, and behavioral metrics.

---

## Technical Overview

Modern security architectures often struggle with high false-positive noise and delayed breach detection. ShadowLure addresses these challenges by shifting the asymmetric advantage back to network defenders through active deception chaining.

Key Operational Properties:

- Zero False Positives: Decoy assets are non-operational traps. Any traffic directed toward a ShadowLure asset indicates high-confidence unauthorized activity.
- Dynamic Token Provisioning: Operators can provision custom canary tokens for any tech stack (AWS S3, PostgreSQL, Kubernetes, Internal APIs) on demand, receiving dynamic UUIDs and tailored decoy payloads.
- Multihop Breadcrumb Traps: Decoys do not terminate at a single point. Accessing an initial AWS S3 decoy reveals secondary breadcrumbs leading to PostgreSQL databases, Kubernetes secrets, and internal API tokens.
- Realistic Synthetic Telemetry: Instead of dropping TCP connections or returning generic HTTP errors, ShadowLure returns believable synthetic S3 bucket listings, database query result sets, and Kubernetes YAML manifests to prolong adversary engagement.
- Automated Attacker Profiling: Fingerprints incoming HTTP user agents, request cadence, automation script signatures, and network connection metadata to construct a comprehensive threat dossier.

---

## System Architecture and Layer Breakdown

ShadowLure is architected as a modular, decoupled C# .NET 9 solution separated into clean layer boundaries:

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
                       | (EF Core, SQLite, LLM, Alerting)|
                       +---------------------------------+
```

### Component Modules

1. ShadowLure.Core: Contains domain entities, enums, value objects, database schema definitions (`CanaryToken`, `AttackerSession`, `TriggerEvent`, `CanaryLink`), and interface abstractions.
2. ShadowLure.Shadow: Implements the active deception engine (`IShadowEngine`), generating dynamic synthetic S3 directory structures, SQL query datasets, and Kubernetes secrets for any registered token ID.
3. ShadowLure.Profiling: Houses the behavioral analytics pipeline (`IBehavioralProfiler`), generating SHA-256 client fingerprints, detecting CLI automation patterns, calculating chain depths, and scoring threat risk levels.
4. ShadowLure.Infrastructure: Handles data persistence via Entity Framework Core, Prometheus metric instrumentation (`MetricsService`), LLM threat summary synthesis, and external webhook notification integrations.
5. ShadowLure.Api: Serves as the Minimal API entry point, HTMX server-side rendering host, Server-Sent Events (SSE) stream server, and interactive operator dashboard host.

---

## Core Capabilities

### 1. Dynamic Decoy Provisioning Engine
Operators are not restricted to pre-configured templates. Through the interactive dashboard or API, operators specify any target environment (e.g., `Enterprise AWS Production`, `Staging Database Cluster`). The engine generates a unique `Guid`, crafts matching decoy credentials, and registers dynamic shadow routing handlers automatically.

### 2. Active Deception Chaining
Deception assets are interconnected via directional links. Accessing an AWS S3 decoy returns synthetic responses embedded with breadcrumbs pointing to database tokens. Following the database breadcrumbs reveals Kubernetes secrets and API keys, creating a multi-stage decoy chain that tracks attacker progression step by step.

### 3. Live Operator Cockpit and Circular Topology Graph
The web dashboard features an interactive circular network graph powered by Vis.js Network with custom physics constraints (`barnesHut`). Activated nodes transition in real time from cyan (active) to rose/red (intercepted), while curved edge labels display exact breadcrumb locations with stroke-padded background rendering for clear legibility.

### 4. Server-Sent Events (SSE) Telemetry Stream
Real-time events bypass traditional polling via a high-throughput SSE endpoint (`/api/events/stream`). Incoming attacker interactions automatically trigger lightweight DOM updates, recalculating Risk Scores, updating Threat Level indicators, and re-rendering Attacker Profile cards without requiring page refreshes.

### 5. Forensic Attacker Intelligence Dossier
Operators can launch the Forensic Attacker Dossier modal to inspect full session analytics:
- Real Connection IP & Network Connection Metadata
- User-Agent Client Fingerprint & CLI Security Tool Classifier
- Automation Detection Status (Interactive Shell vs. Automated Recon Script)
- Risk Score Calculation (0-100 scale: Low, Medium, High, Critical)
- Dynamic Threat Intelligence Behavioral Summary
- Execution Chronology Trace Table containing full un-truncated HTTP request payloads and deception response payloads.

---

## Technology Stack

- Backend Framework: C# .NET 9 Minimal APIs
- Object-Relational Mapper: Entity Framework Core 9.0
- Data Persistence: SQLite / EF Core Relational Engine
- Frontend Logic & Interactivity: HTMX 2.0 (Server-Side HTML Fragments & SSE Swap)
- Styling & Design System: Vanilla CSS & Tailwind CSS Engine
- Graph Visualization: Vis.js Network Engine (Radial Elliptical Layouts & Barnes-Hut Physics)
- Smooth Scrolling & Reveal Animations: Lenis 1.1 Smooth Scroll & GSAP 3.12 ScrollTrigger
- Observability & Metrics: Prometheus Client Library (`prometheus-net`)
- Application Server: Kestrel Web Server

---

## API Reference Specification

### Dynamic Shadow Endpoints (Attacker Trap Targets)

Shadow routes handle incoming requests dynamically for any provisioned canary token `Guid`:

| HTTP Method | Route | Description |
|---|---|---|
| POST | `/api/shadow/aws/{tokenId:guid}` | Traps AWS CLI/S3 requests for token `tokenId`, returning synthetic S3 file listings. |
| POST | `/api/shadow/db/{tokenId:guid}` | Traps SQL database requests for token `tokenId`, returning synthetic CSV/SQL data. |
| POST | `/api/shadow/k8s/{tokenId:guid}` | Traps Kubernetes cluster secret requests for token `tokenId`, returning fake secret YAMLs. |
| POST | `/api/shadow/api/{tokenId:guid}` | Traps API token invocations for token `tokenId`, returning fake internal JSON data. |

### Operator Dashboard Endpoints

| HTTP Method | Route | Description |
|---|---|---|
| GET | `/` | Renders the Widescreen Operator Cockpit. |
| GET | `/api/events/stream` | Opens an SSE connection streaming live telemetry event cards. |
| GET | `/api/cockpit/stats` | Returns real-time JSON metrics, risk scores, and profile state. |
| GET | `/api/graph/data` | Returns Vis.js network nodes and edge links JSON structure. |
| GET | `/api/canaries/modal` | Renders the HTML modal for deploying custom contextual canary tokens. |
| POST | `/api/canaries` | Creates a new custom decoy token dynamically and registers its shadow routes. |
| GET | `/api/canaries/{id}/details` | Renders the inspection modal containing exact PowerShell test commands for token `{id}`. |
| DELETE | `/api/canaries/{id}` | Revokes and deletes a specific canary token from the database. |
| GET | `/api/attacker/details` | Renders the Forensic Attacker Dossier Modal with full HTTP logs. |
| POST | `/api/simulate/step` | Advances the simulation scenario by one decoy interception step. |
| POST | `/api/reset` | Resets all trigger events and restores the seed workspace state. |
| GET | `/metrics` | Exposes Prometheus metrics format for scraping. |

---

## Dynamic Decoy Testing Guide

To test any deployed decoy token (seeded or custom-created):

### 1. Provision or Select a Canary Token
Click **Deploy Canary** on the dashboard to create a custom token, or select any existing token from the **Canary Registry** table.

### 2. Inspect Dynamic Command
Click **Inspect** on the target token's row in the table. The inspection modal automatically generates the tailored PowerShell command with that token's unique `Guid`.

### 3. General Command Pattern
```powershell
curl.exe -X POST http://localhost:5246/api/shadow/{serviceType}/{your-token-guid} -H "User-Agent: {tool-signature}" -d "{payload}"
```

### 4. Service Type Map
- AWS S3 Decoy: Service type path = `aws`
- PostgreSQL Database Decoy: Service type path = `db`
- Kubernetes Secret Decoy: Service type path = `k8s`
- Internal API Decoy: Service type path = `api`

---

## Local Setup and Installation

### Prerequisites

- .NET 9.0 SDK
- Git
- PowerShell / Command Prompt

### Build and Run Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/Shinu-Cherian/ShadowLure.git
   cd ShadowLure
   ```

2. Restore dependencies and build the solution:
   ```bash
   dotnet build ShadowLure.sln
   ```

3. Launch the application server:
   ```bash
   dotnet run --project src/ShadowLure.Api/ShadowLure.Api.csproj --launch-profile http
   ```

4. Access the web dashboard:
   Open `http://localhost:5246` in your browser.

---

## Author

Developed by Shinu Cherian as an active cyber defense research project.
