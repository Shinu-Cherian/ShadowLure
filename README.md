# ShadowLure

Active Deception Architecture and Honeytoken Orchestration Engine

ShadowLure is an enterprise-grade active cyber defense platform designed to detect, track, and profile unauthorized network intruders. Unlike conventional passive honeypots or static canaries that issue a single binary alert, ShadowLure deploys dynamic, contextual deception chains across cloud infrastructure, database environments, Kubernetes clusters, and API gateways. When an adversary interacts with a seeded lure, ShadowLure traps the threat actor inside an instrumented decoy path, serving high-fidelity simulated responses while capturing real-time forensic telemetry, tool fingerprints, and behavioral metrics.

---

## Technical Overview

Modern security architectures often struggle with high false-positive noise and delayed breach detection. ShadowLure addresses these challenges by shifting the asymmetric advantage back to network defenders through active deception chaining.

Key Operational Properties:

- Zero False Positives: Decoy assets are non-operational traps. Any traffic directed toward a ShadowLure asset indicates high-confidence unauthorized activity.
- Multihop Breadcrumb Traps: Decoys do not terminate at a single point. Accessing an initial AWS S3 decoy reveals secondary breadcrumbs leading to PostgreSQL databases, Kubernetes secrets, and internal API tokens.
- Realistic Synthetic Telemetry: Instead of dropping TCP connections or returning generic HTTP errors, ShadowLure returns believable synthetic S3 bucket listings, database query result sets, and Kubernetes YAML manifests to prolong adversary engagement.
- Automated Attacker Profiling: Fingerprints incoming HTTP user agents, request cadence, automation script signatures, and network connection metadata to construct a comprehensive threat dossier.

---

## Architecture and Component Breakdown

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

1. ShadowLure.Core: Contains domain entities, enums, values objects, database schema definitions (`CanaryToken`, `AttackerSession`, `TriggerEvent`, `CanaryLink`), and interface abstractions.
2. ShadowLure.Shadow: Implements the active deception engine (`IShadowEngine`), generating synthetic S3 directory structures, SQL query datasets, and Kubernetes secrets.
3. ShadowLure.Profiling: Houses the behavioral analytics pipeline (`IBehavioralProfiler`), generating SHA-256 client fingerprints, detecting CLI automation patterns, calculating chain depths, and scoring threat risk levels.
4. ShadowLure.Infrastructure: Handles data persistence via Entity Framework Core, Prometheus metric instrumentation (`MetricsService`), LLM threat summary synthesis, and external webhook notification integrations.
5. ShadowLure.Api: Serves as the Minimal API entry point, HTMX server-side rendering host, Server-Sent Events (SSE) stream server, and interactive operator dashboard host.

---

## Core Capabilities

### 1. Active Deception Chaining
Deception assets are interconnected via directional links. When an attacker accesses `prod-s3-replication-key`, the synthetic response contains breadcrumbs pointing to `customer-ledger-readonly`. Accessing the database returns credentials pointing to `eks-payments-secret`, creating a multi-stage decoy chain that tracks attacker progression.

### 2. Live Operator Cockpit and Circular Topology Graph
The web dashboard features an interactive circular network graph powered by Vis.js Network with custom physics constraints (`barnesHut`). Activated nodes transition in real time from cyan (active) to rose/red (intercepted), while curved edge labels display exact breadcrumb locations with padded badge rendering for visual clarity.

### 3. Server-Sent Events (SSE) Telemetry Stream
Real-time events bypass traditional polling via a high-throughput SSE endpoint (`/api/events/stream`). Incoming attacker interactions automatically trigger lightweight DOM updates, recalculating Risk Scores, updating Threat Level indicators, and re-rendering Attacker Profile cards without requiring manual page refreshes.

### 4. Forensic Attacker Intelligence Dossier
Operators can launch the Forensic Attacker Dossier modal to inspect full session analytics:
- Real Connection IP & Network Metadata
- User-Agent Client Fingerprint & CLI Security Tool Classifier
- Automation Detection Status (Interactive Shell vs. Automated Recon Script)
- Risk Score Calculation (0-100 scale: Low, Medium, High, Critical)
- Dynamic Threat Intelligence Summary
- Execution Chronology Trace Table containing full un-truncated HTTP request payloads and deception response payloads.

---

## Technology Stack

- Backend Framework: C# .NET 9 Minimal APIs
- Object-Relational Mapper: Entity Framework Core 9.0
- Data Persistence: SQLite / EF Core Relational Engine
- Frontend Logic & Interactivity: HTMX 2.0 (Server-Side HTML Fragments & SSE Swap)
- Styling & Design System: Modern Vanilla CSS & Tailwind CSS Engine
- Graph Visualization: Vis.js Network Engine (Radial Elliptical Layouts & Barnes-Hut Physics)
- Smooth Scrolling & Reveal Animations: Lenis 1.1 Smooth Scroll & GSAP 3.12 ScrollTrigger
- Observability & Metrics: Prometheus Client Library (`prometheus-net`)
- Application Server: Kestrel Web Server

---

## API Reference Specification

### Deception Endpoints (Attacker Targets)

| HTTP Method | Route | Description |
|---|---|---|
| POST | `/api/shadow/aws/{tokenId}` | Handles AWS S3 decoy requests, returning synthetic S3 listings. |
| POST | `/api/shadow/db/{tokenId}` | Handles database connection lures, returning synthetic SQL query results. |
| POST | `/api/shadow/k8s/{tokenId}` | Handles Kubernetes decoy access, returning synthetic secret YAMLs. |
| POST | `/api/shadow/api/{tokenId}` | Handles internal API decoy requests, returning fake invoice JSONs. |

### Operator Dashboard Endpoints

| HTTP Method | Route | Description |
|---|---|---|
| GET | `/` | Renders the Widescreen Dashboard Operator Cockpit. |
| GET | `/api/events/stream` | Opens an SSE connection streaming live telemetry event cards. |
| GET | `/api/cockpit/stats` | Returns real-time JSON metrics, risk scores, and profile state. |
| GET | `/api/graph/data` | Returns Vis.js network nodes and edge links JSON structure. |
| GET | `/api/canaries/modal` | Renders the HTML modal for deploying new contextual canary tokens. |
| POST | `/api/canaries` | Creates a new canary decoy token and appends it to the registry. |
| GET | `/api/canaries/{id}/details` | Renders the inspection modal containing PowerShell test commands. |
| DELETE | `/api/canaries/{id}` | Revokes and deletes a specific canary token from the database. |
| GET | `/api/attacker/details` | Renders the Forensic Attacker Dossier Modal with full HTTP logs. |
| POST | `/api/simulate/step` | Advances the simulation scenario by one decoy interception step. |
| POST | `/api/reset` | Resets all trigger events and restores the seed workspace state. |
| GET | `/metrics` | Exposes Prometheus metrics format for scraping. |

---

## Verification and Testing Guide

Follow these step-by-step commands to verify deception triggers in Microsoft Windows PowerShell:

### 1. AWS S3 Decoy Interception
```powershell
curl.exe -X POST http://localhost:5246/api/shadow/aws/c2d77a06-444f-4eb8-b9a3-577823fcae6d -H "User-Agent: aws-cli/2.15.10" -d "aws s3 ls --recursive s3://prod-s3-replication"
```

### 2. PostgreSQL Database Decoy Interception
```powershell
curl.exe -X POST http://localhost:5246/api/shadow/db/e5f1b2c3-8899-4d5e-a1b2-3c4d5e6f7a8b -H "User-Agent: psql/16.1" -d "SELECT * FROM customer_ledgers LIMIT 5"
```

### 3. Kubernetes Secret Decoy Interception
```powershell
curl.exe -X POST http://localhost:5246/api/shadow/k8s/f6a7b8c9-0011-4223-b334-5d6e7f8a9b0c -H "User-Agent: kubectl/v1.30 (linux/amd64)" -d "kubectl get secrets -A -o yaml"
```

### 4. Internal API Decoy Interception
```powershell
curl.exe -X POST http://localhost:5246/api/shadow/api/a1b2c3d4-e5f6-4789-8012-3456789abcde -H "User-Agent: python-requests/2.32" -d "GET /v1/internal/invoices?tenant=enterprise"
```

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
