// ─── SwarmScan Shared Types & API Contracts ──────────────────────────────────
// This file is the single source of truth for data shapes across the
// control plane (Next.js), execution plane (scan-engine) and the frontend.
// It is owned by the orchestrator — subagents must NOT edit it.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ConfidenceBand = "suspected" | "likely" | "confirmed";
export type ScanStatus =
  | "queued"
  | "planning"
  | "running"
  | "verifying"
  | "completed"
  | "killed"
  | "failed";
export type AgentRunStatus =
  | "dormant"
  | "pending"
  | "running"
  | "done"
  | "blocked"
  | "skipped"
  | "killed";
export type PolicyTier = "safe" | "standard" | "aggressive";
export type ScanProfile = "quick" | "full" | "continuous";
export type ScanScope = "internal" | "external";
export type TargetKind = "host" | "cidr" | "url";
export type TargetEnvironment = "lab" | "external";
export type EvidenceKind =
  | "oob_callback"
  | "boolean_diff"
  | "time_contrast"
  | "error_match"
  | "dom_taint"
  | "version_map"
  | "reverify"
  | "decision";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function bandOf(confidence: number): ConfidenceBand {
  if (confidence >= 85) return "confirmed";
  if (confidence >= 60) return "likely";
  return "suspected";
}

/** Bayesian posterior: P = (prior·∏LR) / (1 + prior·∏LR), expressed 0–99 */
export function bayesianConfidence(priorOdds: number, lrProduct: number): number {
  const odds = priorOdds * lrProduct;
  const p = odds / (1 + odds);
  return Math.round(p * 99 * 10) / 10;
}

// ─── Entities (serialized JSON shapes returned by the API) ──────────────────

export interface EvidenceItem {
  id: string;
  findingId: string | null;
  scanId: string;
  kind: EvidenceKind;
  lr: number;
  content: string;
  hash: string;
  prevHash: string;
  sequence: number;
  createdAt: string;
}

export interface Finding {
  id: string;
  scanId: string;
  agentKey: string;
  title: string;
  severity: Severity;
  category: string;
  confidence: number;
  band: ConfidenceBand;
  target: string;
  endpoint: string | null;
  cve: string | null;
  description: string;
  pocScript: string | null;
  priorOdds: number;
  likelihood: number;
  createdAt: string;
  evidence?: EvidenceItem[];
  scan?: { id: string; target: string; status: string };
}

export interface AgentRun {
  id: string;
  scanId: string;
  agentKey: string;
  agentName: string;
  version: string;
  state: string;
  status: AgentRunStatus;
  progress: number;
  requests: number;
  findings: number;
  startedAt: string | null;
  endedAt: string | null;
}

export interface TargetItem {
  id: string;
  name: string;
  value: string;
  scope: ScanScope;
  environment: TargetEnvironment;
  kind: TargetKind;
  authorized: boolean;
  attestedBy: string | null;
  attestedAt: string | null;
  note: string | null;
  createdAt: string;
}

export interface CreateTargetPayload {
  name: string;
  value: string;
  scope: ScanScope;
  environment?: TargetEnvironment;
  note?: string;
  authorized?: boolean;
  attestedBy?: string;
}

export interface ScanSummary {
  id: string;
  target: string;
  scope: ScanScope;
  profile: ScanProfile;
  status: ScanStatus;
  seed: string;
  policyTier: PolicyTier;
  progress: number;
  requestCount: number;
  agentCount: number;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
  findingsCount?: number;
  findingsBySeverity?: Record<string, number>;
}

export interface EventLogItem {
  id: string;
  scanId: string | null;
  type: string;
  message: string;
  meta?: string | null;
  createdAt: string;
}

export interface ChainStep {
  title: string;
  action: string;
  status: "pending" | "approved" | "executed" | "failed";
  findingId?: string | null;
}

export interface ChainGraphNode {
  id: string;
  label: string;
  type: "asset" | "finding" | "credential" | "impact";
  severity?: string;
  detail?: string;
  x?: number; // layout hint 0..100 for graph rendering
  y?: number; // layout hint 0..100 for graph rendering
}

export interface ChainGraphEdge {
  from: string;
  to: string;
  label: string;
}

export interface AttackChainItem {
  id: string;
  scanId: string;
  name: string;
  severity: Severity;
  verified: boolean;
  currentStep: number;
  steps: ChainStep[];
  graph: { nodes: ChainGraphNode[]; edges: ChainGraphEdge[] };
}

export interface ScanDetail extends ScanSummary {
  agentRuns: AgentRun[];
  findings: Finding[];
  chains: AttackChainItem[];
  events: EventLogItem[];
}

export interface PolicyItem {
  id: string;
  name: string;
  kind: string;
  code: string;
  enabled: boolean;
  updatedAt: string;
}

export interface ScopeRuleItem {
  id: string;
  name: string;
  cidrs: string[];
  mode: "allowlist" | "denylist";
  enforced: boolean;
}

// ─── Integrations: 47-connector catalog + per-connection state ───────────────
// Catalog metadata (why / agent benefit / mistakes → guardrails) lives in
// src/lib/swarm/integrations-catalog.ts — the DB only stores connection state.

export type IntegrationCategory =
  | "recon"
  | "vulnerability"
  | "threat-intel"
  | "ticketing"
  | "siem"
  | "soar"
  | "communication"
  | "data"
  | "identity"
  | "mcp"
  | "ai"
  | "architecture"
  | "cicd"
  | "secrets";

/** outbound = findings leave the control plane; inbound = external context flows in */
export type IntegrationDirection = "outbound" | "inbound";

/**
 * Truthful connection lifecycle — derived SERVER-SIDE, never guessed client-side.
 *   not_configured — required config fields are missing
 *   unverified     — config complete but no passing test on the current config
 *   failed         — the most recent connection test failed
 *   disabled       — verified configuration, switched off by an analyst
 *   connected      — enabled AND verified (the server refuses any other pair)
 */
export type IntegrationConnState =
  | "not_configured"
  | "unverified"
  | "failed"
  | "disabled"
  | "connected";

export type IntegrationAuth =
  | "api-key"
  | "oauth2"
  | "token"
  | "webhook"
  | "basic"
  | "native"
  | "none";

export interface IntegrationFieldSpec {
  key: string;
  label: string;
  /** masked in every API response — value never leaves the server after save */
  secret?: boolean;
  required?: boolean;
  placeholder?: string;
}

/** Server-enforced guardrails derived from the "common implementation mistakes". */
export interface IntegrationGuardrails {
  /** max dispatch/sync calls per minute → 429 beyond */
  rateLimitPerMin?: number;
  /** dispatch must carry explicit analyst approval → 403 otherwise */
  requiresApproval?: boolean;
  /** dispatched finding targets must pass active scope rules */
  scopeEnforced?: boolean;
  /** skip findings whose evidence key was already dispatched here */
  dedupeByEvidence?: boolean;
  /** the named field must be pinned to an immutable ref (never latest/main) */
  pinnedVersion?: string;
  /** payloads are redacted/minimized before leaving the control plane */
  dataMinimization?: boolean;
  /** agent access is read-only — no write operations exposed */
  readOnly?: boolean;
}

export interface IntegrationItem {
  id: string;
  key: string;
  name: string;
  category: IntegrationCategory;
  direction: IntegrationDirection;
  auth: IntegrationAuth;
  enabled: boolean;
  /** stored values — secret fields are redacted to "" in responses */
  config: Record<string, string>;
  /** keys that have a stored (server-side) value, secrets included */
  configSet: string[];
  description: string;
  agentBenefit: string;
  cautions: string[];
  guardrails: IntegrationGuardrails;
  fields: IntegrationFieldSpec[];
  /** outbound reference prefix, e.g. "VULN" → VULN-1042 */
  refPrefix?: string;
  /** server-derived truthful lifecycle state — "connected" implies enabled && verified */
  connState: IntegrationConnState;
  lastTest: { at: string; ok: boolean; latencyMs: number; detail: string } | null;
  lastSyncAt: string | null;
  stats: { dispatched: number; activityEvents: number };
}

/** PUT /api/integrations/:id response — the merged item plus policy side-effects. */
export interface IntegrationUpdateResponse {
  integration: IntegrationItem;
  /** true when a config change auto-disconnected the connector pending re-verification */
  autoDisabled?: boolean;
  /** human explanation of any policy side-effect that occurred */
  notice?: string;
}

export interface IntegrationTestResponse {
  ok: boolean;
  latencyMs: number;
  detail: string;
  /** validation problems — empty when ok */
  issues: string[];
  checkedAt: string;
}

/** Chained verify-and-connect request — save (optional) → test → enable. */
export interface IntegrationConnectPayload {
  /** config patch to persist before testing (secrets blank = keep stored) */
  config?: Record<string, string>;
}

export interface IntegrationDispatchItem {
  ref: string;
  findingId: string;
  title: string;
  severity: Severity;
  target: string;
  /** short evidence-hash prefix used for cross-integration dedup */
  evidenceKey: string;
}

export interface IntegrationDispatchResponse {
  ok: boolean;
  dispatched: number;
  skippedDuplicates: number;
  skippedOutOfScope: number;
  items: IntegrationDispatchItem[];
  error?: string;
}

export interface IntegrationSyncMetric {
  label: string;
  value: number;
  unit?: string;
}

export interface IntegrationSyncResponse {
  ok: boolean;
  summary: string;
  metrics: IntegrationSyncMetric[];
  syncedAt: string;
  error?: string;
}

export type IntegrationActivityAction =
  | "test"
  | "dispatch"
  | "sync"
  | "toggle"
  | "config";

export interface IntegrationActivityEvent {
  id: string;
  action: IntegrationActivityAction;
  message: string;
  createdAt: string;
}

export interface IntegrationActivityResponse {
  events: IntegrationActivityEvent[];
}

export interface IntegrationDispatchPayload {
  approve?: boolean;
  limit?: number;
  minSeverity?: Severity;
}

export interface AgentCatalogEntry {
  key: string;
  name: string;
  version: string;
  safetyClass: "read-only" | "data-touching";
  category: string;
  description: string;
  states: string[];
  consumes: string[];
  emits: string[];
  stage: number; // DAG stage in the scan plan
  /** dynamic agents are never statically planned — they sit dormant until
   *  their runtime spawn trigger fires, then join the scan mid-flight. */
  dynamic?: boolean;
  /** human-readable spawn trigger description (dynamic agents only). */
  spawnOnDesc?: string;
  /** unorthodox = attacker tradecraft outside the textbook canon. */
  unorthodox?: boolean;
  /** one-line "why this hurts" for the unorthodox family. */
  tradecraft?: string;
}

// ─── Engine socket events (port 3003 via ?XTransformPort=3003) ──────────────

export interface EngineScanUpdate {
  scanId: string;
  status: ScanStatus;
  progress: number;
  requestCount: number;
}

export interface EngineAgentUpdate {
  scanId: string;
  agentKey: string;
  agentName: string;
  version: string;
  state: string;
  status: AgentRunStatus;
  progress: number;
  requests: number;
  findings: number;
}

export interface EngineFindingNew {
  scanId: string;
  finding: Finding;
}

export interface EngineEventNew {
  scanId?: string | null;
  type: string;
  message: string;
  ts: string;
}

export interface EngineKilled {
  scanId?: string | null;
  latencyMs: number;
  message: string;
}

export interface EngineStats {
  activeScans: number;
  requestsPerMin: number;
  workers: number;
  uptimeSec: number;
  bus: "connected" | "degraded";
}

// ─── OOB Interaction Server (spec §1.1 data plane) ─────────────────────────

export type OobProtocol = "dns" | "http" | "smtp" | "smb";

export interface OobCallback {
  id: string;
  protocol: OobProtocol;
  canary: string;
  domain: string; // e.g. r2e8k4m9.oob.swarmscan.io
  sourceIp: string;
  target: string; // originating target of the scan
  agentKey: string;
  detail: string; // e.g. "A 10.0.0.2 · resolver 10.0.0.2" or "GET / 200 84ms"
  ts: string;
}

export interface EngineOobNew {
  callback: OobCallback;
}

export interface OobStats {
  dns: number;
  http: number;
  smtp: number;
  smb: number;
  last24h: number;
  uniqueCanaries: number;
}

// ─── Scope firewall — eBPF-enforced egress telemetry (kernel-level scope) ────

export type FirewallVerdict = "allow" | "deny";

export interface FirewallPacket {
  id: string;
  ts: string;
  rule: string; // e.g. "corp-egress" | "default-deny"
  cidr: string; // matched CIDR
  srcIp: string; // worker sandbox egress IP
  dstIp: string;
  dstPort: number;
  worker: string; // e.g. "worker-3"
  agent: string; // agent key
  verdict: FirewallVerdict;
  reason: string; // "in-scope · rule corp-egress" | "out-of-scope — dropped at eBPF hook"
  bytes: number;
}

export interface FirewallRuleState {
  label: string;
  cidr: string;
  mode: "enforced" | "monitoring";
  allowed: number;
  denied: number;
}

export interface FirewallStats {
  packetsTotal: number;
  allowed: number;
  denied: number;
  denyRatePerMin: number;
  enforcedRules: number;
  windowPps: number; // current offer rate through the wall
}

export interface EngineFirewallNew {
  packet: FirewallPacket;
}

// ─── Capacity learning (spec §5.2 — per-target adaptive rate models) ────────

export type CapacityStatus = "learning" | "stable" | "backoff";

export interface CapacityTarget {
  target: string; // host
  ip: string;
  status: CapacityStatus;
  ewmaCapRps: number; // learned safe req/s (EWMA α=0.2)
  offeredRps: number;
  acceptedRps: number;
  p50Ms: number;
  p95Ms: number;
  status429: number;
  status503: number;
  retryAfterSec: number | null;
  backoffUntil: string | null; // ISO
  backoffMultiplier: number;
  samples: number;
  spark: number[]; // last 24 offered/cap ratios
}

export interface FirewallSnapshot {
  stats: FirewallStats;
  rules: FirewallRuleState[];
  packets: FirewallPacket[]; // recent (ring buffer)
  capacity: CapacityTarget[];
}

// ─── Benchmark corpus (spec §6 — the scanner's CI) ──────────────────────────

export interface BenchmarkRunRow {
  id: string;
  runKey: string;
  agentKey: string;
  agentName: string;
  total: number;
  passed: number;
  failed: number;
  fnRate: number;
  fpRate: number;
  durationMs: number;
  seed: string;
  createdAt: string;
}

export interface BenchmarkAggregate {
  total: number;
  passed: number;
  failed: number;
  fnRate: number;
  fpRate: number;
  detectionRate: number;
  durationMs: number;
  sloMet: boolean;
}

export interface BenchmarkSummaryResponse {
  totalCases: number;
  agents: number;
  bySource: { source: string; count: number }[];
  bySeverity: Record<string, number>;
  byDifficulty: Record<string, number>;
  slo: { fnTarget: number; fpTarget: number };
  latestRun: {
    runKey: string;
    seed: string;
    createdAt: string;
    rows: BenchmarkRunRow[];
    aggregate: BenchmarkAggregate;
  } | null;
  history: {
    runKey: string;
    createdAt: string;
    detectionRate: number;
    fpRate: number;
    sloMet: boolean;
  }[];
}

export interface BenchmarkRunResponse {
  runKey: string;
  seed: string;
  rows: BenchmarkRunRow[];
  aggregate: BenchmarkAggregate;
}

// ─── CI release gates (benchmark corpus → agent registry publish gating) ────

export type CiGateStatus = "passed" | "failed" | "running";

export interface CiGateRow {
  id: string;
  agentKey: string;
  agentName: string;
  releaseTag: string; // e.g. "injection.sql@1.4.0"
  runKey: string; // benchmark run the verdict evaluated
  status: CiGateStatus;
  detectionRate: number; // %
  fnRate: number; // %
  fpRate: number; // %
  durationMs: number;
  verdictAt: string; // ISO
  note: string; // human verdict line
}

export interface CiGatesSummary {
  total: number;
  passed: number;
  failed: number;
  lastEvaluatedAt: string | null;
}

export interface CiGatesResponse {
  gates: CiGateRow[];
  summary: CiGatesSummary;
}

export interface CiEvaluateResponse extends CiGatesResponse {
  evaluated: number;
  changed: number;
}

// ─── GraphQL output plane — finding-graph explorer (Task 9-a) ───────────────
// POST /api/graphql { query, variables } → GqlResponse<T>. The explorer view
// drives its graph canvas from the result of a `graph(...)` query.

export type GraphNodeKind = "target" | "scan" | "agent" | "finding" | "chain";
export type GraphEdgeKind = "scoped" | "executed" | "produced" | "correlated";

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  sub: string; // secondary caption (e.g. "17 findings · 94.2% avg conf")
  severity?: Severity;
  band?: ConfidenceBand;
  status?: string; // scan status / agent run status
}

export interface GraphEdge {
  id: string;
  source: string; // node id
  target: string; // node id
  kind: GraphEdgeKind;
}

export interface GraphStats {
  nodes: number;
  edges: number;
  targets: number;
  scans: number;
  agents: number;
  findings: number;
  chains: number;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
}

export interface GqlGraphResult {
  graph: GraphData;
}

export interface GqlError {
  message: string;
  locations?: { line: number; column: number }[];
}

export interface GqlResponse<T = unknown> {
  data?: T | null;
  errors?: GqlError[];
  latencyMs?: number; // server-side execution time
}

// ─── Access control — RBAC / SSO / sessions / API keys (Task 9-b) ───────────
// GET /api/access → AccessResponse; POST /api/access (AccessAction) mutates.

export type AccessRole = "owner" | "admin" | "operator" | "auditor" | "viewer";

export interface AccessUser {
  id: string;
  email: string;
  name: string;
  role: AccessRole;
  team: string;
  status: "active" | "suspended";
  mfa: boolean;
  provider: string; // "okta-saml" | "auth0-oidc" | "local"
  lastLoginAt: string | null;
  createdAt: string;
}

export interface AccessSessionItem {
  id: string;
  userName: string;
  userEmail: string;
  role: AccessRole;
  ip: string;
  ua: string;
  location: string;
  method: string; // "SSO · SAML" | "SSO · OIDC" | "Password + MFA"
  startedAt: string;
  lastSeenAt: string;
  expiresAt: string;
}

export interface ApiKeyItem {
  id: string;
  label: string;
  prefix: string; // visible fragment, e.g. "ssk_live_7f3a…"
  scopes: string[];
  createdBy: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface SsoConnectionItem {
  id: string;
  kind: "saml" | "oidc" | "scim";
  name: string;
  status: "connected" | "pending" | "disabled";
  domain: string;
  detail: string; // entityId / client id / scim endpoint
  userCount: number;
  lastSyncAt: string | null;
}

export interface PermissionRow {
  key: string; // e.g. "scans:launch"
  label: string;
  description: string;
  roles: AccessRole[]; // roles granted this permission
}

export interface AccessStats {
  users: number;
  activeSessions: number;
  mfaCoverage: number; // %
  ssoCoverage: number; // % of users authenticating via SSO
  activeKeys: number;
}

export interface AccessResponse {
  users: AccessUser[];
  sessions: AccessSessionItem[];
  apiKeys: ApiKeyItem[];
  sso: SsoConnectionItem[];
  permissions: PermissionRow[];
  stats: AccessStats;
}

export type AccessAction =
  | { action: "user.role"; id: string; role: AccessRole; actor?: AccessRole }
  | { action: "user.status"; id: string; status: "active" | "suspended" }
  | { action: "session.revoke"; id: string }
  | { action: "key.create"; label: string; scopes: string[] }
  | { action: "key.revoke"; id: string }
  | { action: "sso.status"; id: string; status: SsoConnectionItem["status"] };

export interface AccessMutationResponse {
  ok: boolean;
  message: string;
  key?: { id: string; secret: string; label: string }; // present only on key.create
}

// ─── PR range scanning — CI merge gate (Task 10-a) ──────────────────────────
// A PR arrives with a unified diff → the planner derives a RANGE-LIMITED scan
// (only affected routes + relevant agents) → engine runs it against the PR's
// preview deployment with a deterministic seed → the verdict gates the merge.

export type PrChangeType = "added" | "modified" | "deleted" | "renamed";

export interface PrDiffLine {
  type: "add" | "del" | "ctx";
  text: string;
}

export interface PrDiffHunk {
  header: string; // "@@ -18,9 +18,26 @@ func registerRoutes()"
  lines: PrDiffLine[];
}

export interface PrFileChange {
  path: string;
  changeType: PrChangeType;
  additions: number;
  deletions: number;
  hunks: PrDiffHunk[];
}

export interface PrPlanAgent {
  key: string;
  name: string;
  reason: string; // why this agent is in the range plan
}

export interface PrRangePlan {
  seed: string; // deterministic: derived from repo + pr number
  target: string; // preview deployment URL scanned by the engine
  routes: string[]; // affected routes/surfaces extracted from the diff
  agents: PrPlanAgent[];
  estimatedRequests: number;
  scopeReductionPct: number; // % of the equivalent full-scan plan skipped
  skipReason: string | null; // e.g. "documentation-only diff — no attack surface touched"
}

export type PrVerdict = "pending" | "running" | "pass" | "fail" | "skipped";

export interface PrItem {
  id: string; // deterministic: "pr-{repo-slug}-{number}"
  repo: string;
  prNumber: number;
  title: string;
  author: string;
  branch: string; // "feature-x → main"
  files: PrFileChange[];
  additions: number;
  deletions: number;
  plan: PrRangePlan;
  verdict: PrVerdict;
  scanId: string | null; // linked Scan once launched
  scanStartedAt: string | null; // ISO — when the linked scan started
  scanCompletedAt: string | null; // ISO — when the linked scan verified
  blockingFindings: number; // critical/high + confirmed/likely from the linked scan
  createdAt: string;
}

export interface PrListResponse {
  prs: PrItem[];
}

export interface PrRunResponse {
  ok: boolean;
  scanId: string;
  message: string;
}

// ─── Supply chain — Sigstore bundles + SLSA provenance (Task 10-b) ──────────
// Every agent release is a signed WASM bundle: ed25519 signature over the
// bundle digest, Fulcio-issued cert bound to the builder identity, Rekor
// transparency-log inclusion, SLSA L3 provenance. Unsigned pushes quarantine.

export type BundleStatus = "signed" | "unsigned" | "quarantined";

export interface AgentBundle {
  agentKey: string;
  agentName: string;
  releaseTag: string; // e.g. "injection@1.4.0"
  status: BundleStatus;
  sizeBytes: number;
  bundleHash: string; // sha256 of the wasm bundle
  signedAt: string | null;
  signature: { keyId: string; algorithm: string; sigHex: string } | null;
  certificate:
    | {
        subject: string; // builder identity (workflow ref)
        issuer: string;
        validFrom: string;
        validTo: string;
        serial: string;
        fingerprint: string;
      }
    | null;
  tlog: { logId: string; logIndex: number; integratedAt: string; rootHash: string } | null;
  provenance:
    | {
        slsaLevel: "L3";
        builder: string;
        builderId: string;
        materials: { uri: string; digest: string }[];
        byproducts: { name: string; digest: string }[];
        reproducible: boolean;
        invocation: string; // workflow invocation ref
      }
    | null;
  note?: string; // quarantine reason for non-signed bundles
}

export interface SigningResponse {
  bundles: AgentBundle[];
  summary: {
    total: number;
    signed: number;
    quarantined: number;
    slsaLevel: "L3";
    lastVerifiedAt: string | null;
  };
}

export interface SignVerifyStep {
  label: string;
  status: "passed" | "failed" | "skipped";
  detail: string;
  ms: number;
}

export interface SignVerifyResponse {
  agentKey: string;
  releaseTag: string;
  verified: boolean;
  steps: SignVerifyStep[];
  durationMs: number;
}

// ─── Multi-tenant sharding — consistent-hash ring (Task 11-a) ────────────────
// Spec §4 data plane: targets are partitioned across the worker fleet with a
// consistent-hash ring — sha256(target) → angle, owner = nearest vnode
// clockwise. Worker add/remove migrates ONLY the keys between the
// departure/arrival arc and its clockwise neighbor; everything else stays
// put. The ring is the reason scale-out is incremental, not a full reshuffle.

export type ShardWorkerStatus = "healthy" | "draining" | "joining" | "offline";
export type ShardMigrationReason = "rebalance" | "drain" | "join";
export type ShardTargetState = "stable" | "migrating";

export interface ShardWorker {
  id: string; // "w-04"
  region: string; // "us-east-1"
  status: ShardWorkerStatus;
  vnodes: number; // owned ring slots
  targets: number; // owned targets
  loadPct: number; // capacity utilization 0-100
  rps: number; // live request rate through this worker
  uptimeSec: number;
  joinedAt: string; // ISO
}

export interface ShardTarget {
  id: string; // host
  tenant: string;
  angleDeg: number; // ring position 0-360
  workerId: string; // owning worker id
  state: ShardTargetState;
  migratingTo: string | null;
  weight: number; // relative scan weight (endpoints × depth)
}

export interface ShardMigration {
  id: string;
  targetId: string;
  fromWorkerId: string;
  toWorkerId: string;
  reason: ShardMigrationReason;
  progressPct: number; // 0-100 keyspace moved
  startedAt: string; // ISO
  etaSec: number;
}

export interface ShardStats {
  workers: number;
  vnodes: number; // ring slots (workers × vnodesPerWorker)
  targets: number;
  tenants: number;
  movingKeysPct: number; // keyspace in flight 0-100
  balanceScore: number; // 0-100 (100 = perfectly even target spread)
  totalRps: number;
  migrationsTotal: number; // lifetime handoffs completed
}

export interface ShardHistoryPoint {
  t: string; // ISO
  balanceScore: number;
  movingKeysPct: number;
}

export interface ShardSnapshot {
  stats: ShardStats;
  workers: ShardWorker[];
  targets: ShardTarget[];
  migrations: ShardMigration[];
  history: ShardHistoryPoint[]; // rolling spark (~48 points)
}

export interface EngineShardNew {
  type: "handoff" | "join" | "drain" | "rebalance";
  message: string;
  targetId?: string;
  fromWorkerId?: string;
  toWorkerId?: string;
  at: number; // epoch ms
}

export type ShardAction = "add-worker" | "remove-worker" | "rebalance";

export interface ShardActionResponse {
  ok: boolean;
  message: string;
  workers?: number;
}

// ─── Compliance — SOC 2 export packs + scheduler (Task 11-b) ─────────────────
// Spec §7: auditors get point-in-time evidence bundles cut from the WORM
// ledger — control → evidence mapping with chain-head attestation, and a
// scheduler that snapshots the pack on a cadence (deliveries land in the
// audit trail, never as side-channel files).

export type ControlStatus = "satisfied" | "partial" | "gap";

export interface ComplianceEvidenceRef {
  entryId: string;
  sequence: number; // ledger sequence number
  kind: string; // evidence kind
  hash: string;
  at: string; // ISO
  findingTitle: string | null;
}

export interface ComplianceControl {
  id: string; // "CC6.1"
  title: string;
  description: string;
  status: ControlStatus;
  coveragePct: number; // 0-100 evidence coverage
  evidenceCount: number;
  evidence: ComplianceEvidenceRef[]; // capped for UI (~6)
  gapNote: string | null;
}

export interface CompliancePack {
  framework: "SOC 2 Type II";
  periodStart: string; // ISO date
  periodEnd: string; // ISO date
  generatedAt: string; // ISO
  controls: ComplianceControl[];
  summary: {
    satisfied: number;
    partial: number;
    gaps: number;
    evidenceEntries: number;
    ledgerValid: boolean;
    chainHead: string;
    findingsCovered: number;
  };
}

export interface ComplianceExportOptions {
  includeRawEvidence: boolean;
  includeSarif: boolean;
  anonymize: boolean;
}

export interface ComplianceExportResponse {
  ok: boolean;
  fileName: string;
  sizeBytes: number;
  entries: number;
  controls: number;
  downloadedAt: string; // ISO
  manifest: { section: string; entries: number; sha256: string }[];
}

export type SchedulerJobStatus = "enabled" | "paused";

export interface SchedulerJob {
  id: string;
  name: string;
  cron: string; // 5-field cron
  humanCron: string; // "Every Monday 08:00 UTC"
  format: "soc2" | "sarif" | "executive";
  status: SchedulerJobStatus;
  nextRunAt: string; // ISO
  lastRunAt: string | null; // ISO
  lastStatus: "success" | "failed" | null;
  lastDurationMs: number | null;
  deliveries: number; // audit-trail rows written by this job
}

export interface SchedulerListResponse {
  jobs: SchedulerJob[];
}

export interface SchedulerMutationResponse {
  ok: boolean;
  message: string;
}

// ─── GitHub check-run CI reporting (Task 11-c) ───────────────────────────────
// PR Guard verdicts surface where merges actually happen: the GitHub Checks
// API. Reporting is a first-class mutation — the payload is persisted in the
// EventLog audit trail (type "ci") so the check-run state is reconstructable.

export interface CheckRunPayload {
  checkRunId: number; // deterministic GitHub check-run id
  name: string; // "SwarmScan / range-scan"
  repo: string; // "acme-corp/internal-tools"
  prNumber: number;
  status: "queued" | "in_progress" | "completed";
  conclusion: "success" | "failure" | "skipped" | "neutral" | null;
  outputTitle: string; // "MERGE BLOCKED — 3 blocking findings"
  outputSummary: string; // summary shown in the Checks tab
  annotationsCount: number; // one annotation per blocking finding
  detailsUrl: string; // deep-link back to PR Guard
  startedAt: string | null; // ISO
  completedAt: string | null; // ISO
}

export interface CheckRunReportResponse {
  ok: boolean;
  check: CheckRunPayload;
  message: string;
}

export interface CheckRunStateResponse {
  check: CheckRunPayload | null;
}

// ─── GitHub App check-run feed (Task 12-c) ──────────────────────────────────
// The Integrations view surfaces the check-runs PR Guard has reported: the
// feed is the EventLog audit trail (type "ci"), so it reflects exactly what
// GitHub would show — no side-channel state.

export interface CheckRunFeedEntry {
  id: string; // EventLog row id
  repo: string;
  prNumber: number;
  prId: string; // deep-link back to PR Guard
  status: "queued" | "in_progress" | "completed";
  conclusion: "success" | "failure" | "skipped" | "neutral" | null;
  outputTitle: string;
  checkRunId: number;
  annotationsCount: number;
  reportedAt: string; // ISO
}

export interface CheckRunFeedResponse {
  entries: CheckRunFeedEntry[];
  total: number;
  repos: { repo: string; prs: number; lastAt: string }[];
}

// ─── Continuous monitoring — scheduled profiles + drift detection (Task 13) ──
// Spec revisit story: scheduled profiles continuously re-scan targets; the
// RevisitAgent fingerprints findings (agentKey + title) and diffs consecutive
// runs — drift (new / regressed / remediated / unchanged) feeds alerts and a
// per-profile executive risk score trendline. Engine sim on :3003 broadcasts
// monitoring:new / drift:new / alert:new on the socket bus.

export type MonitoringProfileStatus = "active" | "paused";

export type DriftKind = "new" | "regressed" | "remediated" | "unchanged";

export type MonitoringAlertSeverity = "critical" | "high" | "medium" | "info";

export type MonitoringAlertState = "open" | "acked" | "dismissed";

export interface MonitoringDriftSummary {
  new: number;
  regressed: number;
  remediated: number;
  unchanged: number;
}

export interface MonitoringProfile {
  id: string; // "mp-payments"
  target: string; // "https://payments-api.cyart.io"
  label: string; // "Payments API — continuous assurance"
  cadence: string; // cron display "*/30 * * * *"
  cadenceHuman: string; // "Every 30 minutes"
  window: string; // politeness window "09:00–17:00 UTC"
  status: MonitoringProfileStatus;
  lastRunAt: string | null; // ISO
  nextRunAt: string; // ISO
  runsTotal: number;
  consecutiveClean: number; // completed runs with zero new/regressed drift
  driftSummary: MonitoringDriftSummary; // last completed run
  riskScore: number; // 0-100 executive risk (severity-weighted open findings)
  riskTrend: number[]; // rolling ~24 points for the sparkline
}

export interface MonitoringRun {
  id: string; // "run-0231"
  profileId: string;
  trigger: "schedule" | "manual" | "drift-recheck";
  status: "running" | "completed" | "failed";
  startedAt: string; // ISO
  completedAt: string | null; // ISO
  durationSec: number;
  findingsTotal: number;
  drift: MonitoringDriftSummary;
  riskScore: number | null; // post-run risk (null while running)
}

export interface DriftEntry {
  id: string;
  profileId: string;
  runId: string;
  fingerprint: string; // stable "agentKey:title" identity across runs
  agentKey: string;
  findingTitle: string;
  severity: Severity; // current severity
  kind: DriftKind;
  prevSeverity: Severity | null;
  prevConfidence: number | null;
  confidence: number; // current
  detail: string; // "confidence 61→79 · WAF rule changed since last run"
  at: string; // ISO
}

export interface MonitoringAlert {
  id: string;
  profileId: string;
  runId: string | null;
  severity: MonitoringAlertSeverity;
  state: MonitoringAlertState;
  title: string; // "New Critical finding — payments-api"
  detail: string;
  driftEntryId: string | null;
  raisedAt: string; // ISO
  ackedAt: string | null;
  ackedBy: string | null; // acting role label
}

export interface MonitoringStats {
  profilesActive: number;
  profilesPaused: number;
  runs24h: number;
  driftNew24h: number;
  driftRemediated24h: number;
  openAlerts: number;
  meanRisk: number; // avg risk across active profiles, 0-100
}

export interface MonitoringSnapshot {
  stats: MonitoringStats;
  profiles: MonitoringProfile[];
  runs: MonitoringRun[]; // recent, newest first (~40)
  drift: DriftEntry[]; // recent, newest first (~60)
  alerts: MonitoringAlert[]; // recent, newest first (~30)
}

export interface EngineMonitoringNew {
  kind: "run-started" | "run-completed" | "profile-updated" | "risk-changed";
  message: string;
  profileId: string;
  runId?: string;
  at: number; // epoch ms
}

export interface EngineDriftNew {
  entry: DriftEntry;
}

export interface EngineAlertNew {
  alert: MonitoringAlert;
}

export type MonitoringActionKind =
  | "pause"
  | "resume"
  | "run-now"
  | "ack-alert"
  | "dismiss-alert";

export interface MonitoringActionPayload {
  action: MonitoringActionKind;
  profileId?: string;
  alertId?: string;
  by?: string; // acting role label for ack attribution
}

export interface MonitoringActionResponse {
  ok: boolean;
  message: string;
}

// ─── Composite API responses ─────────────────────────────────────────────────

export interface FindingsListResponse {
  findings: Finding[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AgentRegistryResponse {
  agents: (AgentCatalogEntry & { runs: number; findings: number; avgConfidence: number })[];
}

export interface LedgerResponse {
  entries: (EvidenceItem & { findingTitle: string | null; scanTarget: string })[];
  total: number;
}

export interface AttackGraphResponse {
  chains: AttackChainItem[];
}

export interface PoliciesResponse {
  policies: PolicyItem[];
  scopeRules: ScopeRuleItem[];
}

export interface IntegrationsResponse {
  integrations: IntegrationItem[];
}

export interface EngineToolStatus {
  name: string;
  available: boolean;
}

export interface EngineHealthResponse {
  ok: boolean;
  activeScans: number;
  workers: number;
  uptimeSec: number;
  lastKillLatencyMs: number | null;
  tools?: EngineToolStatus[];
}

export interface EngineKillResponse {
  ok: boolean;
  latencyMs: number;
  message: string;
  killed: number;
}

export interface IngestPayload {
  scanId: string;
  status: "completed" | "killed" | "failed";
  requestCount: number;
  agentRuns: Omit<AgentRun, "id" | "scanId" | "startedAt" | "endedAt">[];
  findings: {
    agentKey: string;
    title: string;
    severity: Severity;
    category: string;
    confidence: number;
    band: ConfidenceBand;
    target: string;
    endpoint: string | null;
    cve: string | null;
    description: string;
    pocScript: string | null;
    priorOdds: number;
    likelihood: number;
    createdAt: string;
    evidence: { kind: EvidenceKind; lr: number; content: string; hash: string; prevHash: string; sequence: number }[];
  }[];
  events: { type: string; message: string; meta?: string | null }[];
  chains?: {
    name: string;
    severity: Severity;
    steps: ChainStep[];
    graph: { nodes: ChainGraphNode[]; edges: ChainGraphEdge[] };
  }[];
}

export interface OverviewResponse {
  kpis: {
    activeScans: number;
    totalScans: number;
    requestsPerMin: number;
    killLatencyMs: number;
    fpRate: number | null; // % from the latest benchmark corpus run; null = never benchmarked
    detectionRate: number | null; // % recall from the latest benchmark run; null = never benchmarked
    confirmedFindings: number;
    totalFindings: number;
  };
  severity: Record<Severity, number>;
  bands: Record<ConfidenceBand, number>;
  agentActivity: {
    agentKey: string;
    name: string;
    findings: number;
    avgConfidence: number;
    runs: number;
  }[];
  recentFindings: Finding[];
  recentEvents: EventLogItem[];
  engine: { healthy: boolean; activeScans: number; workers: number; uptimeSec: number; tools?: EngineToolStatus[] };
}

export interface LedgerVerifyResponse {
  valid: boolean;
  checked: number;
  brokenAt: number | null;
  headHash: string;
  checkedAt: string;
}

export interface CreateScanPayload {
  targetId: string;
  profile: ScanProfile;
  policyTier: PolicyTier;
  /** acting principal's role — required to authorize the aggressive/destructive tier */
  actingRole?: AccessRole;
  seed?: string;
  agents?: string[];
}

export interface ReportResponse {
  scanId: string;
  target: string;
  format: "executive" | "technical" | "sarif" | "remediation";
  generatedAt: string;
  // executive
  riskScore?: number;
  executiveSummary?: string;
  riskBreakdown?: { label: string; count: number; color: string }[];
  topChains?: { name: string; severity: string; verified: boolean }[];
  // technical & remediation
  findings?: Finding[];
  remediations?: unknown[];
  // sarif
  sarif?: unknown;
}

// ─── Fetch helper ────────────────────────────────────────────────────────────

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${body ? ` — ${body.slice(0, 200)}` : ""}`);
  }
  return res.json() as Promise<T>;
}
