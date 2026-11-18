# SwarmScan — Platform Architecture, Technical Specifications & Tech Stack

SwarmScan is an autonomous, enterprise-grade penetration testing and vulnerability scanning swarm platform. It is engineered with a strict two-plane separation: a **Next.js 16 Control Plane** for orchestration, analytics, policy enforcement, and reporting, and an independent **Scan Engine Execution Plane** for real-time, deterministic, and safe distributed agent probing.

---

## 1. What SwarmScan Does

SwarmScan transforms traditional monolithic, signature-based vulnerability scanning into an autonomous **multi-agent swarm** that mirrors real-world attacker tradecraft while upholding strict enterprise safety boundaries.

### Key Capabilities
* **Autonomous Multi-Agent Recon & Testing:** Deploys an orchestrated DAG (Directed Acyclic Graph) of specialized security agents across 6 coordinated stages.
* **Dynamic & Unorthodox Tradecraft:** Beyond standard CVE checks, SwarmScan deploys unorthodox agents (cache poisoning, HTTP request smuggling, SAML signature wraps, race conditions, and business logic flaws) and dynamic agents that awaken mid-flight based on runtime findings (e.g. Shadow API discovery, credential reuse, network pivoting).
* **Bayesian Likelihood Confidence Engine:** Discards arbitrary 1–10 scoring. It computes statistically sound Bayesian probabilities based on prior odds and evidence likelihood ratios ($LR$) to categorize findings into confidence bands: `suspected`, `likely`, or `confirmed`.
* **WORM (Write-Once-Read-Many) Evidence Ledger:** Every observed probe response, time-contrast anomaly, error trace, and out-of-band callback is cryptographically hashed and chained (`sha256(prevHash + sequence + content)`), creating a tamper-evident audit trail suitable for regulatory and legal compliance.
* **Correlated Attack Graphs:** Automatically stitches disparate low- and medium-severity findings into end-to-end multi-hop attack chains (e.g., SSRF on internal asset $\to$ cloud IMDS token extraction $\to$ privilege escalation).
* **Deterministic Scope & Safety Firewall:** Enforces mandatory operator authorization attestations before any network packet is dispatched. Validates CIDR allowlists/denylists, enforces 24-hour permissible testing windows, respects OPA/Rego rate limits, and features a global SIGKILL emergency halt (<10ms latency).
* **Scanner CI & Benchmark Corpus:** Includes a regression evaluation suite that tests agents against known target corpora to mathematically verify that false-positive rates stay below 2% and detection rates exceed 90% before publishing agent releases.
* **Standardized Reporting & Compliance:** Generates Executive Risk Dashboards, granular Technical Finding Reports, and OASIS SARIF 2.1 outputs with cross-mappings to SOC 2, ISO 27001, and PCI-DSS controls.

---

## 2. High-Level System Architecture

SwarmScan separates user interaction and orchestration from active probing:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CONTROL PLANE (Port 3000)                             │
│                                                                                 │
│   Next.js 16 App Router · React 19 · Tailwind CSS 4 · shadcn/ui · Recharts       │
│                                                                                 │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────────┐  │
│  │   SOC Live Overview   │  │   Scan Orchestration  │  │  Findings & WORM    │  │
│  │   & Event Bus Feed    │  │   & 6-Stage DAG Viz   │  │  Evidence Ledger    │  │
│  └───────────────────────┘  └───────────────────────┘  └─────────────────────┘  │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────────┐  │
│  │   Attack Graph Viewer │  │  Rego Policies/Scope  │  │  SARIF & Executive  │  │
│  │   & Kill-Chains       │  │  Firewall & Windows   │  │  Compliance Reports │  │
│  └───────────────────────┘  └───────────────────────┘  └─────────────────────┘  │
│                                                                                 │
│   API Route Handlers (REST & GraphQL) · Zod Schemas · Zustand · TanStack Query │
│                                  │                                              │
│                                  ▼                                              │
│                  Prisma ORM 6.11 · SQLite Database                             │
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
               Socket.IO Event Bus │ HTTP RPC Commands (/start, /kill)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      SCAN ENGINE EXECUTION PLANE (Port 3003)                    │
│                                                                                 │
│   Standalone Node.js Service (TSX) · Socket.IO Server · Real-Time Worker Pool   │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │  Safety Wall: Scope Resolver · Target Authorization Gate · Private CIDR │   │
│   └────────────────────────────────────┬────────────────────────────────────┘   │
│                                        │                                        │
│   ┌────────────────────────────────────▼────────────────────────────────────┐   │
│   │                        6-Stage Agent Pipeline DAG                       │   │
│   │                                                                         │   │
│   │  Stage 0: Recon & Surface Discovery (CT logs, SaaS takeover, DNS)       │   │
│   │  Stage 1: Multi-Signal Fingerprinting (WAF profiling, tech hashes)      │   │
│   │  Stage 2: Headless Crawler & SSRF Introspection                         │   │
│   │  Stage 3: Vulnerability Scanners (SQLi, XSS, Path Traversal, Deser)     │   │
│   │  Stage 4: Auth, API, Crypto, Cloud, Business Logic & Race Conditions    │   │
│   │  Stage 5: Attack Graph Correlation, Revisit Verification & Evasion      │   │
│   └────────────────────────────────────┬────────────────────────────────────┘   │
│                                        │                                        │
│   ┌────────────────────────────────────▼────────────────────────────────────┐   │
│   │  Deterministic Probes & Tool Adapters (Nuclei, Nmap, Httpx, Raw Sockets)│   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. How It Works (End-to-End Workflow)

### Stage 1: Target Registration & Operator Attestation
1. An operator registers a target URL, hostname, or CIDR block in the **Targets** registry.
2. The operator explicitly confirms permissions by setting `authorized = true` and declaring the environment (`external` for non-destructive detection only vs. `lab` for active exploitation verification).
3. The scope engine verifies target boundaries against allowlists and denylists before any scan can be scheduled.

### Stage 2: Scan Creation & Policy Evaluation
1. The operator launches a scan through the 2-step **New Scan Wizard** in the Control Plane UI.
2. The scan profile (`quick`, `full`, or `continuous`) and policy tier (`safe`, `standard`, `aggressive`) are selected.
3. If `safe` tier is selected, all data-touching offensive agents are automatically locked and excluded.
4. Active OPA/Rego policies evaluate rate limits, payload classes, and active permissible scanning time windows (e.g., restricted to off-peak hours).

### Stage 3: Execution Plane Hand-Off
1. The Control Plane calls `POST http://localhost:3003/start` with the scan ID, target details, cryptographic seed, and selected agent keys.
2. The Scan Engine initializes an internal state machine (FSM) for each agent and kicks off the 6-stage DAG.
3. As agents make progress, real-time events (`scan:update`, `agent:update`, `finding:new`, `event:new`) stream back to the UI over the **Socket.IO** bus.

### Stage 4: 6-Stage Agent Execution Pipeline
The agents run sequentially by stage and in parallel within each stage:
* **Stage 0 (Recon):** Passive-first discovery via Certificate Transparency (CT) logs, passive DNS, ASN mapping, sub-domain permutation, and 40+ SaaS takeover heuristics.
* **Stage 1 (Fingerprint):** Multi-signal fusion via ETag headers, mmh2 favicon hashing, JS bundle chunk analysis, and WAF/CDN behavioral probing to prepare evasion strategies.
* **Stage 2 (Crawl & SSRF):** Headless DOM walking, endpoint extraction, hidden parameter identification, and cloud metadata (IMDSv1/v2) SSRF testing.
* **Stage 3 (Core Vulnerabilities):** Automated, deterministic scanners check for SQL injection, reflected/stored XSS, path traversal, file inclusion, prototype pollution, and serialization flaws.
* **Stage 4 (Service, Identity & Cloud):** Checks API schemas, broken object-level authorization (BOLA), JWT/SAML flaws, cloud misconfigurations, race conditions, and business logic inconsistencies.
* **Stage 5 (Correlation, Revisit & Evasion):**
  * `CorrelatorAgent` analyzes all verified findings to synthesize attack chains (e.g. chaining info disclosure to SSRF to admin takeover).
  * `RevisitAgent` tests previous findings using altered timing or payload variations to eliminate transient anomalies.
  * Dynamic agents (e.g. `ShadowApiAgent`, `PivotAgent`) spawn only if earlier stages uncover specific trigger conditions.

### Stage 5: Bayesian Analysis & WORM Ledger Ingestion
1. For every observation, the system computes the likelihood ratio ($LR$).
2. Bayesian posterior confidence is updated using:
   $$\text{Posterior Odds} = \text{Prior Odds} \times \prod LR_i$$
   $$\text{Confidence} = \frac{\text{Posterior Odds}}{1 + \text{Posterior Odds}} \times 100$$
3. The finding is saved into the database along with its cryptographic evidence block:
   $$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} + \text{Sequence}_n + \text{Content}_n)$$
4. Any tamper attempt invalidates the entire chain, guaranteeing forensic integrity.

### Stage 6: Triaging, Attack Graphing & Export
1. Findings are displayed in the interactive SOC dashboard with severity distribution and confidence donuts.
2. The operator can explore visualized kill-chains in the **Attack Graph Explorer**.
3. Compliance reports (Executive Summary, Technical Audit, and SARIF 2.1) are generated on demand.

---

## 4. Comprehensive Tech Stack Breakdown

### Frontend (Control Plane UI)
| Technology | Version | Purpose |
| :--- | :--- | :--- |
| **Next.js** | `^16.1.1` | React framework using App Router for server-rendered shell and client views |
| **React** | `^19.0.0` | Core UI library for declarative component trees |
| **TypeScript** | `^5.0.0` | Strict static typing across all data models, UI props, and API contracts |
| **Tailwind CSS** | `^4.0.0` | Modern CSS-first utility styling with custom dark SOC emerald palette |
| **shadcn/ui & Radix UI** | Latest | Accessible unstyled primitives (Dialogs, Dropdowns, Tabs, Accordions, Toasts) |
| **Framer Motion** | `^12.23.2` | Fluid animations for KPI counters, pipeline stage pulses, and transitions |
| **Recharts** | `^2.15.4` | Responsive SVG charts (severity breakdown, confidence donut, risk gauges) |
| **TanStack Query** | `^5.82.0` | Asynchronous state management, server cache invalidation, and polling |
| **TanStack Table** | `^8.21.3` | High-performance virtualized sorting and filtering for finding tables |
| **Zustand** | `^5.0.6` | Lightweight client navigation store (active view, active scan, active finding) |
| **Socket.IO Client** | `^4.8.4` | Real-time WebSocket connection to the scan execution plane |
| **Lucide React** | `^0.525.0` | Unified iconography for SOC alerts, agent statuses, and severity badges |

### Backend & Orchestration (Control Plane APIs)
| Technology | Version | Purpose |
| :--- | :--- | :--- |
| **Next.js Route Handlers** | `16.x` | Edge/Node REST endpoints for scans, targets, findings, and policies |
| **Prisma ORM** | `^6.11.1` | Type-safe database queries and migrations |
| **SQLite** | `v3` | Embedded, zero-configuration local database for scans, logs, and evidence |
| **Zod** | `^4.0.2` | Runtime schema validation for all API inputs and engine payloads |
| **GraphQL** | `^17.0.2` | Flexible query interface for integrations and custom reporting queries |
| **NextAuth.js** | `^4.24.11` | Enterprise session handling, SSO scaffolding (SAML / OIDC), and RBAC |

### Execution Plane (Scan Engine Mini-Service)
| Technology | Version | Purpose |
| :--- | :--- | :--- |
| **Node.js** | `20+` | Execution runtime for async network I/O and worker concurrency |
| **TypeScript & tsx** | `^4.19.2` | TypeScript execution without precompilation overhead |
| **Socket.IO Server** | `^4.8.4` | Low-latency bi-directional telemetry broadcast to the control plane |
| **Native HTTP Server** | Node stdlib | REST endpoints (`/health`, `/scans`, `/start`, `/kill`) |
| **Tool Integration Layer** | Custom | Gracefully detects and bridges CLI tools (Nuclei, Nmap, Httpx, Naabu, Katana) |

### Security, Cryptography & Compliance
* **Cryptographic Hashing:** Node.js `crypto` SHA-256 for deterministic seed derivation, asset hashing, and WORM evidence chain integrity.
* **OPA / Rego:** Declarative policy evaluation for payload classification, time-window gating, and rate limiting.
* **SARIF 2.1:** OASIS standard format export for GitHub Advanced Security and enterprise SIEM ingestion.

---

## 5. Directory & File Structure Guide

```
Swarm-Scan/
├── prisma/
│   └── schema.prisma             # Data schema (Scan, Finding, Evidence, Target, Policy, etc.)
├── mini-services/
│   └── scan-engine/              # Execution plane microservice (Port 3003)
│       ├── index.ts              # HTTP & Socket.IO server setup
│       └── lib/
│           ├── agents.ts         # Agent specifications, DAG definitions & FSM states
│           ├── engine.ts         # ScanEngine DAG orchestrator & lifecycle manager
│           ├── findings.ts       # Bayesian probability calculator & WORM hash chain
│           ├── probes.ts         # Safe network probes (TLS, DNS, HTTP, Secrets, Ports)
│           ├── scanners.ts       # Vulnerability scanner implementations (SQLi, XSS, etc.)
│           ├── scope.ts          # Scope firewall, IP validation & CIDR checker
│           ├── chain.ts          # Attack-chain synthesis engine
│           └── tools.ts          # External CLI tool detector (Nuclei, Nmap, etc.)
├── src/
│   ├── app/                      # Next.js App Router (pages and API routes)
│   │   ├── api/                  # REST API routes (scans, findings, targets, engine, etc.)
│   │   ├── globals.css           # Custom dark SOC theme & styling
│   │   ├── layout.tsx            # Root HTML layout and metadata
│   │   └── page.tsx              # Control plane entry point
│   ├── components/
│   │   ├── swarm/                # SwarmScan domain components
│   │   │   ├── layout/           # App shell, navigation sidebar, header & kill-switch
│   │   │   ├── overview/         # Dashboard KPI cards, charts, live terminal event bus
│   │   │   ├── scans/            # Scan table, 2-step creation dialog, live DAG pipeline
│   │   │   ├── findings/         # Findings table, Bayesian detail modal, evidence chain
│   │   │   ├── attack-graph/     # Multi-node visual attack graph & kill-chains
│   │   │   ├── policies/         # OPA Rego editor, scope firewall & time-window gauge
│   │   │   ├── reports/          # Executive risk gauge, technical report, SARIF viewer
│   │   │   └── views/            # 14 high-level view containers
│   │   └── ui/                   # Reusable shadcn/ui components (Radix primitives)
│   └── lib/
│       ├── db.ts                 # Global Prisma client singleton
│       └── swarm/
│           ├── agents-catalog.ts # 34-agent master registry with FSM definitions
│           ├── types.ts          # Universal type contracts for APIs, models, and sockets
│           ├── ui-store.ts       # Zustand view router and selection state
│           └── server/           # Backend server logic (scope, CI gates, compliance)
├── Caddyfile                     # Reverse proxy configuration
├── package.json                  # Root dependencies & scripts
└── README.md                     # Quickstart documentation
```

---

## 6. How to Run & Verify

1. **Install dependencies:**
   ```bash
   npm install
   cd mini-services/scan-engine && npm install && cd ../..
   ```

2. **Initialize SQLite Database:**
   ```bash
   npm run db:push
   ```

3. **Start the Control Plane:**
   ```bash
   npm run dev
   # Accessible at http://localhost:3000
   ```

4. **Start the Scan Engine:**
   ```bash
   cd mini-services/scan-engine
   npm run dev
   # Accessible at http://localhost:3003
   ```
