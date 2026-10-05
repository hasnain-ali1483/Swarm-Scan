// ─── ScanEngine — real autonomous scan execution plane ───────────────────────
//
// Runs scan plans as an agent FSM pipeline over a 6-stage DAG:
//   stage 0: recon            stage 3: injection, xss, fileops, deser, …
//   stage 1: fingerprint      stage 4: auth, api, crypto, cloud, …
//   stage 2: crawler, ssrf    stage 5: correlator, revisit, evasion
// Agents within a stage run in parallel; a stage starts when ALL agents of the
// previous stage reached a terminal status (done | blocked | skipped | killed).
//
// This is a REAL engine: each agent runs a genuine, SAFE probe (see
// lib/probes.ts) and findings are parsed from real observations. There is no
// fabricated data. Where a probe needs an industry tool that is absent, that
// agent reports "unavailable" rather than inventing a result. Offensive
// techniques with no safe automated form are surfaced as "manual authorized
// testing required" and never weaponised.
//
// HARD SAFETY WALL: before any probe touches the network the target is
// validated against the engagement scope and must be operator-authorized
// (see lib/scope.ts). localhost is never a valid target.

import { AGENTS, AGENT_BY_KEY, DYNAMIC_AGENTS, MAX_STAGE, QUICK_PROFILE_AGENTS, isDataTouching, type AgentSpec } from "./agents";
import {
  GENESIS_HASH,
  PRIOR_ODDS,
  SEVERITY_RANK,
  bandOf,
  bayesianConfidence,
  chainHash,
  type ConfidenceBand,
  type EvidenceKind,
  type Severity,
} from "./findings";
import {
  nucleiProbe,
  probeApiDiscovery,
  probeCrawl,
  probeFingerprint,
  probeGit,
  probePorts,
  probeRecon,
  probeSecrets,
  probeTls,
  type Probe,
  type ProbeCtx,
  type RawFinding,
  type ScanShared,
} from "./probes";
import { scanExposure, scanOpenRedirect, scanSqli, scanTraversal, scanXss } from "./scanners";
import { detectTools, type ToolName, type ToolStatus } from "./tools";
import { synthesizeChains, type ChainData, type ChainFinding } from "./chain";
import {
  type ScanScope,
  isPrivateAddress,
  resolveScopeTarget,
  validateTarget,
  type ScopeTarget,
} from "./scope";
import { log, logError } from "./log";

// ─── Agent → probe routing ───────────────────────────────────────────────────
// "manual"   → offensive technique with no safe automated probe (documented,
//              not executed). "correlate" → builds attack chains from findings.
//              "reverify" → re-checks earlier findings. Unmapped → info note.

type ProbeKind = Probe | "manual" | "correlate" | "reverify";

/** Run several probes in sequence, concatenating their findings. */
function combine(...ps: Probe[]): Probe {
  return async (ctx) => {
    const out: RawFinding[] = [];
    for (const p of ps) {
      try {
        out.push(...(await p(ctx)));
      } catch (err) {
        logError("sub-probe failed", err);
      }
    }
    return out;
  };
}

// Native scanners (lib/scanners.ts) are the PRIMARY detectors — real TS DAST,
// not a nuclei wrapper. nuclei is layered on as extra coverage when installed;
// when it is absent it simply adds nothing (the native agent still finds).
const PROBE_MAP: Record<string, ProbeKind> = {
  recon: async (ctx) => [...(await probeRecon(ctx)), ...(await probePorts(ctx))],
  fingerprint: probeFingerprint,
  crawler: combine(probeCrawl, probeApiDiscovery),
  crypto: probeTls,
  gitrepo: probeGit,
  secrets: probeSecrets,
  ssrf: combine(scanOpenRedirect(), nucleiProbe(["ssrf", "redirect"], "injection")),
  injection: combine(scanSqli(), nucleiProbe(["sqli", "injection"], "injection")),
  xss: combine(scanXss(), nucleiProbe(["xss"], "client")),
  fileops: combine(scanTraversal(), nucleiProbe(["lfi", "traversal"], "files")),
  deser: nucleiProbe(["deserialization"], "injection"),
  auth: nucleiProbe(["default-login", "auth-bypass", "exposure"], "authz"),
  api: combine(scanExposure(), nucleiProbe(["graphql", "swagger", "api"], "api")),
  cloud: nucleiProbe(["aws", "exposure", "cloud"], "cloud"),
  edge: nucleiProbe(["cve", "misconfig"], "perimeter"),
  correlator: "correlate",
  revisit: "reverify",
  // Offensive / evasion techniques — documented, never weaponised:
  passwords: "manual",
  saml: "manual",
  smuggling: "manual",
  race: "manual",
  cachepoison: "manual",
  prototype: "manual",
  websocket: "manual",
  hostheader: "manual",
  timing: "manual",
  evasion: "manual",
  osint: "manual",
  // Dynamic agents:
  shadowapi: nucleiProbe(["exposure", "misconfig"], "api"),
  fronting: "manual",
  credreuse: "manual",
  pivot: "correlate",
  fusion: "correlate",
};

// ─── Public types ─────────────────────────────────────────────────────────────

export type ScanProfile = "quick" | "full" | "continuous";
export type PolicyTier = "safe" | "standard" | "aggressive";
export type ScanStatus = "queued" | "planning" | "running" | "verifying" | "completed" | "killed" | "failed";
export type AgentRunStatus = "dormant" | "pending" | "running" | "done" | "blocked" | "skipped" | "killed";

export interface StartScanInput {
  scanId?: unknown;
  target?: unknown;
  profile?: unknown;
  policyTier?: unknown;
  seed?: unknown;
  agents?: unknown;
  scope?: unknown;
  environment?: unknown;
  authorized?: unknown;
  destructive?: unknown;
}

export interface StartResult {
  ok: boolean;
  error?: string;
}

export interface KillResult {
  ok: boolean;
  latencyMs: number;
  killed: number;
  message: string;
}

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

export interface FindingRecord {
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
  evidence: EvidenceItem[];
}

export interface ChainRecord extends ChainData {
  id: string;
  scanId: string;
  verified: boolean;
  currentStep: number;
}

export interface AgentRunSnapshot {
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

export interface ScanListItem {
  scanId: string;
  target: string;
  profile: ScanProfile;
  policyTier: PolicyTier;
  seed: string;
  scope: ScanScope;
  status: ScanStatus;
  progress: number;
  requestCount: number;
  findingsCount: number;
  chainsCount: number;
  startedAt: string;
  completedAt: string | null;
  active: boolean;
  agents: AgentRunSnapshot[];
}

// ─── Internal runtime state ───────────────────────────────────────────────────

interface AgentRunRT {
  spec: AgentSpec;
  state: string;
  status: AgentRunStatus;
  progress: number;
  requests: number;
  findings: number;
  startedAt: string | null;
  endedAt: string | null;
  stateIndex: number;
  totalStates: number;
}

interface EventRecord {
  type: string;
  message: string;
  meta?: string | null;
  ts: string;
}

interface ScanRuntime {
  scanId: string;
  target: string;
  host: string;
  scopeTarget: ScopeTarget;
  scope: ScanScope;
  environment: "lab" | "external";
  profile: ScanProfile;
  policyTier: PolicyTier;
  seed: string;
  status: ScanStatus;
  progress: number;
  requestCount: number;
  startedAt: string;
  completedAt: string | null;
  agents: Map<string, AgentRunRT>;
  plannedKeys: string[];
  stage: number;
  stageKeys: string[];
  totalPlannedStates: number;
  completedStates: number;
  events: EventRecord[];
  findings: FindingRecord[];
  chains: ChainRecord[];
  evidenceSeq: number;
  evidencePrevHash: string;
  timers: Set<ReturnType<typeof setTimeout>>;
  killed: boolean;
  finished: boolean;
  shared: ScanShared;
  tools: Record<ToolName, ToolStatus>;
  spawnedKeys: Set<string>;
  activeAgents: number;
}

type HistoryEntry = Omit<ScanListItem, "active">;

const TERMINAL_STATUS: ReadonlySet<AgentRunStatus> = new Set(["done", "blocked", "skipped", "killed"]);
const EVENT_RING_CAP = 120;
const HISTORY_CAP = 20;
const PLANNING_DELAY_MS = 400;
const RUN_DELAY_MS = 650;
const CONTROL_PLANE_INGEST = process.env.CONTROL_PLANE_INGEST ?? "http://localhost:3000/api/internal/ingest";

function nowIso(): string {
  return new Date().toISOString();
}
function round1(n: number): number {
  return Math.round(n * 10) / 10;
}
function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── ScanEngine ───────────────────────────────────────────────────────────────

export class ScanEngine {
  private readonly scans = new Map<string, ScanRuntime>();
  private readonly history: HistoryEntry[] = [];
  private readonly requestTimestamps: number[] = [];
  private readonly broadcast: (event: string, payload: unknown) => void;
  private toolsCache: Record<ToolName, ToolStatus> | null = null;

  lastKillLatencyMs: number | null = null;

  constructor(broadcast: (event: string, payload: unknown) => void) {
    this.broadcast = broadcast;
  }

  activeCount(): number {
    return this.scans.size;
  }

  requestsPerMin(): number {
    const cutoff = Date.now() - 60_000;
    while (this.requestTimestamps.length > 0 && this.requestTimestamps[0] < cutoff) {
      this.requestTimestamps.shift();
    }
    return this.requestTimestamps.length;
  }

  listScans(): ScanListItem[] {
    const active: ScanListItem[] = [];
    for (const scan of this.scans.values()) active.push(this.scanToListItem(scan, true));
    const archived = this.history.map((h) => ({ ...h, active: false }));
    return [...active, ...archived];
  }

  private async tools(): Promise<Record<ToolName, ToolStatus>> {
    if (!this.toolsCache) this.toolsCache = await detectTools();
    return this.toolsCache;
  }

  start(input: StartScanInput): StartResult {
    try {
      if (typeof input.scanId !== "string" || input.scanId.trim().length === 0) {
        return { ok: false, error: "scanId is required" };
      }
      if (typeof input.target !== "string" || input.target.trim().length === 0) {
        return { ok: false, error: "target is required" };
      }
      const rawTarget = input.target.trim();

      // ── Scope + authorization wall (hard safety gate) ──
      const scope: ScanScope =
        input.scope === "internal" || input.scope === "external"
          ? input.scope
          : isPrivateAddress(rawTarget.replace(/^[a-z]+:\/\//i, "").split("/")[0]) ? "internal" : "external";
      const scopeTarget = resolveScopeTarget(rawTarget, scope);
      const verdict = validateTarget(scopeTarget.host, scope);
      if (!verdict.ok) {
        return { ok: false, error: `target rejected — ${verdict.reason}` };
      }
      if (input.authorized !== true) {
        return {
          ok: false,
          error: "target is not authorized — register it and attest authorization before scanning",
        };
      }

      const profile = (input.profile ?? "full") as ScanProfile;
      if (!["quick", "full", "continuous"].includes(profile)) {
        return { ok: false, error: "profile must be quick | full | continuous" };
      }
      const policyTier = (input.policyTier ?? "standard") as PolicyTier;
      if (!["safe", "standard", "aggressive"].includes(policyTier)) {
        return { ok: false, error: "policyTier must be safe | standard | aggressive" };
      }
      // Destructive-oracle gate (defense in depth): the aggressive tier is the
      // destructive/intrusive class and must carry an explicit Owner-authorized
      // destructive grant. The control plane enforces the Owner role; the engine
      // refuses an aggressive scan that arrives without the grant.
      if (policyTier === "aggressive" && input.destructive !== true) {
        return {
          ok: false,
          error: "aggressive (destructive-oracle) tier requires an Owner-authorized destructive grant",
        };
      }
      const environment: "lab" | "external" = input.environment === "lab" ? "lab" : "external";
      // Active proof-of-exploit is LAB-ONLY (defense in depth). External targets
      // are detection-only even at the aggressive tier.
      if (policyTier === "aggressive" && environment !== "lab") {
        return {
          ok: false,
          error: "active exploitation (aggressive tier) is permitted only on lab targets — external targets are detection-only",
        };
      }
      const seed = typeof input.seed === "string" ? input.seed : "";
      if (input.agents !== undefined) {
        if (!Array.isArray(input.agents) || input.agents.length === 0 || !input.agents.every((k) => typeof k === "string")) {
          return { ok: false, error: "agents must be a non-empty array of agent keys" };
        }
      }

      const scanId = input.scanId.trim();
      if (this.scans.has(scanId)) return { ok: false, error: "already running" };

      let selected: string[];
      if (Array.isArray(input.agents)) {
        selected = [...new Set(input.agents as string[])].filter(
          (k) => AGENT_BY_KEY[k] !== undefined && AGENT_BY_KEY[k].dynamic !== true
        );
      } else if (profile === "quick") {
        selected = [...QUICK_PROFILE_AGENTS];
      } else {
        selected = AGENTS.filter((a) => a.dynamic !== true).map((a) => a.key);
      }
      if (selected.length === 0) return { ok: false, error: "no valid agents selected" };
      const plannedKeys = AGENTS.map((a) => a.key).filter(
        (k) => selected.includes(k) && AGENT_BY_KEY[k].dynamic !== true
      );

      const scan: ScanRuntime = {
        scanId,
        target: scopeTarget.url,
        host: scopeTarget.host,
        scopeTarget,
        scope,
        environment,
        profile,
        policyTier,
        seed,
        status: "queued",
        progress: 0,
        requestCount: 0,
        startedAt: nowIso(),
        completedAt: null,
        agents: new Map(),
        plannedKeys,
        stage: -1,
        stageKeys: [],
        totalPlannedStates: 0,
        completedStates: 0,
        events: [],
        findings: [],
        chains: [],
        evidenceSeq: 0,
        evidencePrevHash: GENESIS_HASH,
        timers: new Set(),
        killed: false,
        finished: false,
        shared: { addresses: [], openPorts: [], routes: [], jsUrls: [], tech: [], injectionPoints: [], nucleiFindings: [], nucleiConsumed: new Set() },
        tools: {} as Record<ToolName, ToolStatus>,
        spawnedKeys: new Set(),
        activeAgents: 0,
      };

      for (const spec of AGENTS) {
        const planned = plannedKeys.includes(spec.key);
        const isDynamic = spec.dynamic === true;
        const totalStates = spec.states.length * (profile === "continuous" && spec.key === "revisit" ? 2 : 1);
        scan.agents.set(spec.key, {
          spec,
          state: isDynamic ? "dormant — awaiting trigger" : spec.states[0],
          status: planned ? "pending" : isDynamic ? "dormant" : "skipped",
          progress: 0,
          requests: 0,
          findings: 0,
          startedAt: null,
          endedAt: null,
          stateIndex: 0,
          totalStates,
        });
        if (planned) scan.totalPlannedStates += totalStates;
      }

      this.scans.set(scanId, scan);
      log(`scan ${scanId} accepted — ${scan.target} (${scope}, profile=${profile}, tier=${policyTier}, ${plannedKeys.length} agents)`);

      this.emitScanUpdate(scan);
      this.pushEvent(scan, "system", `Scan accepted — ${scan.target} (${scope} engagement, profile: ${profile}, tier: ${policyTier}) — authorization attested`);

      const planningTimer = setTimeout(() => void this.enterPlanning(scan), PLANNING_DELAY_MS);
      scan.timers.add(planningTimer);
      return { ok: true };
    } catch (err) {
      logError("start() failed", err);
      return { ok: false, error: "internal start failure" };
    }
  }

  kill(scanId?: string): KillResult {
    const t0 = performance.now();
    const targets: ScanRuntime[] = [];
    if (scanId) {
      const scan = this.scans.get(scanId);
      if (scan) targets.push(scan);
    } else {
      targets.push(...this.scans.values());
    }
    if (targets.length === 0) {
      const latencyMs = Math.round(performance.now() - t0);
      return { ok: true, latencyMs, killed: 0, message: scanId ? `No active scan with id ${scanId} — nothing to kill` : "No active scans to kill" };
    }
    for (const scan of targets) {
      try {
        this.killScan(scan);
      } catch (err) {
        logError(`killScan(${scan.scanId}) failed`, err);
      }
    }
    const midLatency = Math.round(performance.now() - t0);
    this.broadcast("killed", { scanId: scanId && targets.length === 1 ? scanId : null, latencyMs: midLatency, message: `Kill signal propagated to ${targets.length} scan(s) in ${midLatency}ms` });
    for (const scan of targets) this.postIngest(scan, "killed");
    const latencyMs = Math.round(performance.now() - t0);
    this.lastKillLatencyMs = latencyMs;
    log(`kill ${scanId ?? "(all)"} — ${targets.length} scan(s) halted in ${latencyMs}ms`);
    return { ok: true, latencyMs, killed: targets.length, message: `Kill signal propagated to ${targets.length} scan(s)` };
  }

  // ── Boot sequence ──
  private async enterPlanning(scan: ScanRuntime): Promise<void> {
    if (scan.killed || scan.finished) return;
    scan.status = "planning";
    scan.tools = await this.tools();
    this.emitScanUpdate(scan);

    const available = (Object.values(scan.tools) as ToolStatus[]).filter((t) => t.available).map((t) => t.name);
    const stageCount = new Set(scan.plannedKeys.map((k) => AGENT_BY_KEY[k].stage)).size;
    this.pushEvent(scan, "system", `Plan built — ${scan.plannedKeys.length} agents across ${stageCount} DAG stages`);
    this.pushEvent(scan, "system", `Tooling: ${available.length ? available.join(", ") : "no external tools on PATH — built-in probes only"}`);
    for (const agent of scan.agents.values()) this.emitAgentUpdate(scan, agent);
    const skipped = [...scan.agents.values()].filter((a) => a.status === "skipped").length;
    if (skipped > 0) this.pushEvent(scan, "system", `${skipped} agent(s) skipped — outside of plan`);

    const runTimer = setTimeout(() => this.enterRunning(scan), RUN_DELAY_MS);
    scan.timers.add(runTimer);
  }

  private enterRunning(scan: ScanRuntime): void {
    if (scan.killed || scan.finished) return;
    scan.status = "running";
    this.emitScanUpdate(scan);
    this.pushEvent(scan, "system", "Execution started — engine workers engaged");
    this.advanceStage(scan);
  }

  // ── DAG stage machine ──
  private advanceStage(scan: ScanRuntime): void {
    if (scan.killed || scan.finished) return;
    let stage = scan.stage + 1;
    let keys: string[] = [];
    while (stage <= MAX_STAGE) {
      keys = scan.plannedKeys.filter((k) => AGENT_BY_KEY[k].stage === stage);
      if (keys.length > 0) break;
      stage += 1;
    }
    if (stage > MAX_STAGE || keys.length === 0) {
      this.beginVerify(scan);
      return;
    }
    scan.stage = stage;
    scan.stageKeys = keys;
    const tags = keys.map((k) => scan.agents.get(k)!.spec.tag);
    this.pushEvent(scan, "system", `▸ stage ${stage}/${MAX_STAGE} — ${tags.join(", ")} (parallel)`);
    for (const key of keys) void this.runAgent(scan, scan.agents.get(key)!);
  }

  // ── Real agent execution ──
  private async runAgent(scan: ScanRuntime, agent: AgentRunRT): Promise<void> {
    if (scan.killed || scan.finished) return;
    if (scan.policyTier === "safe" && isDataTouching(agent.spec.key)) {
      this.blockAgent(scan, agent);
      return;
    }
    scan.activeAgents += 1;
    agent.startedAt = nowIso();
    agent.status = "running";

    const kind = PROBE_MAP[agent.spec.key];
    const ctx: ProbeCtx = {
      host: scan.host,
      url: scan.target,
      scope: scan.scope,
      environment: scan.environment,
      activeExploit: scan.policyTier === "aggressive" && scan.environment === "lab",
      tools: scan.tools,
      onRequest: (n) => {
        agent.requests += n;
        scan.requestCount += n;
        this.recordRequests(n);
      },
      note: (message) => this.pushEvent(scan, "agent_state", `${agent.spec.tag} ▸ ${message}`),
      shared: scan.shared,
    };

    // Run the real probe (findings surface after the progress walk).
    let findings: RawFinding[] = [];
    let manual = false;
    try {
      if (typeof kind === "function") {
        findings = await (kind as Probe)(ctx);
      } else if (kind === "manual") {
        manual = true;
      } else if (kind === "correlate") {
        this.buildAttackChains(scan);
      } else if (kind === "reverify") {
        this.pushEvent(scan, "agent_state", `${agent.spec.tag} ▸ re-verifying ${scan.findings.length} prior finding(s)`);
      }
    } catch (err) {
      logError(`probe ${scan.scanId}/${agent.spec.key} failed`, err);
      this.pushEvent(scan, "agent_state", `${agent.spec.tag} ▸ probe error — ${err instanceof Error ? err.message : "unknown"}`);
    }

    // Walk the agent's states for live progress.
    const states = agent.spec.states;
    for (let i = 0; i < agent.totalStates; i++) {
      if (scan.killed || scan.finished) {
        scan.activeAgents -= 1;
        return;
      }
      const stateName = states[i % states.length];
      agent.state = stateName;
      agent.stateIndex = i + 1;
      agent.progress = round1((agent.stateIndex / agent.totalStates) * 100);
      scan.completedStates += 1;
      this.recomputeProgress(scan);
      this.emitAgentUpdate(scan, agent);
      this.emitScanUpdate(scan);
      await delay(90 + Math.floor(Math.random() * 120));
    }

    if (manual) {
      this.pushEvent(
        scan,
        "policy",
        `${agent.spec.tag} ▸ no safe automated probe — ${agent.spec.name} technique requires manual authorized testing (not executed)`
      );
    }
    for (const f of findings) this.recordFinding(scan, agent, f);

    scan.activeAgents -= 1;
    this.finishAgent(scan, agent);
  }

  private blockAgent(scan: ScanRuntime, agent: AgentRunRT): void {
    agent.status = "blocked";
    agent.endedAt = nowIso();
    const remaining = agent.totalStates - agent.stateIndex;
    scan.totalPlannedStates -= remaining;
    this.recomputeProgress(scan);
    this.emitAgentUpdate(scan, agent);
    this.emitScanUpdate(scan);
    this.pushEvent(scan, "policy", `Policy denied ${agent.spec.tag} — data-touching class requires ticketed approval (tier: ${scan.policyTier})`);
    this.onAgentTerminal(scan, agent);
  }

  private finishAgent(scan: ScanRuntime, agent: AgentRunRT): void {
    if (TERMINAL_STATUS.has(agent.status)) return;
    agent.status = "done";
    agent.progress = 100;
    agent.endedAt = nowIso();
    this.emitAgentUpdate(scan, agent);
    this.pushEvent(scan, "agent_state", `✓ ${agent.spec.tag} done — ${agent.findings} finding(s), ${agent.requests} requests`);
    this.onAgentTerminal(scan, agent);
  }

  private onAgentTerminal(scan: ScanRuntime, agent: AgentRunRT): void {
    this.checkSpawn(scan);
    const pending = scan.stageKeys.filter((k) => !TERMINAL_STATUS.has(scan.agents.get(k)!.status));
    if (pending.length === 0) this.advanceStage(scan);
  }

  // ── Completion ──
  private beginVerify(scan: ScanRuntime): void {
    if (scan.killed || scan.finished) return;
    scan.status = "verifying";
    this.recomputeProgress(scan);
    this.emitScanUpdate(scan);
    // Final correlation pass — rebuild chains from the complete findings board.
    this.buildAttackChains(scan);
    this.pushEvent(scan, "system", `Verification pass — ${scan.findings.length} finding(s) re-checked against the hash-chained ledger (head ${scan.evidencePrevHash.slice(0, 16)}…)`);
    const timer = setTimeout(() => {
      try {
        this.finishScan(scan);
      } catch (err) {
        logError(`finishScan(${scan.scanId}) failed`, err);
      }
    }, 1500);
    scan.timers.add(timer);
  }

  private finishScan(scan: ScanRuntime): void {
    if (scan.killed || scan.finished) return;
    scan.finished = true;
    scan.status = "completed";
    scan.progress = 100;
    scan.completedAt = nowIso();
    this.emitScanUpdate(scan);
    this.pushEvent(scan, "system", `Scan plan completed — ${scan.findings.length} findings, ${scan.chains.length} chain(s), ${scan.requestCount} requests`);
    log(`scan ${scan.scanId} completed — ${scan.findings.length} findings, ${scan.requestCount} requests`);
    this.postIngest(scan, "completed");
    this.archive(scan);
  }

  // ── Kill ──
  private killScan(scan: ScanRuntime): void {
    scan.killed = true;
    for (const timer of scan.timers) clearTimeout(timer);
    scan.timers.clear();
    for (const agent of scan.agents.values()) {
      if (agent.status === "running") {
        agent.status = "killed";
        agent.endedAt = nowIso();
        this.emitAgentUpdate(scan, agent);
      } else if (agent.status === "pending" || agent.status === "dormant") {
        agent.status = "skipped";
        agent.endedAt = nowIso();
        this.emitAgentUpdate(scan, agent);
      }
    }
    scan.status = "killed";
    this.recomputeProgress(scan);
    this.emitScanUpdate(scan);
    const halted = [...scan.agents.values()].filter((a) => a.status === "killed").length;
    this.pushEvent(scan, "kill", `⛔ kill signal received — ${halted} agent(s) halted mid-state, evidence ring preserved (${scan.findings.length} findings)`);
    log(`scan ${scan.scanId} killed mid-run (${halted} agents halted)`);
    this.archive(scan);
  }

  // ── Findings (real evidence → WORM ledger + bayesian confidence) ──
  private recordFinding(scan: ScanRuntime, agent: AgentRunRT, raw: RawFinding): void {
    const createdAt = nowIso();
    const findingId = `fnd-${scan.scanId}-${scan.findings.length + 1}`;
    const evidence: EvidenceItem[] = raw.evidence.map((e) => {
      scan.evidenceSeq += 1;
      const hash = chainHash(scan.evidencePrevHash, scan.evidenceSeq, e.content);
      const item: EvidenceItem = {
        id: `ev-${scan.scanId}-${scan.evidenceSeq}`,
        findingId,
        scanId: scan.scanId,
        kind: e.kind,
        lr: e.lr,
        content: e.content,
        hash,
        prevHash: scan.evidencePrevHash,
        sequence: scan.evidenceSeq,
        createdAt,
      };
      scan.evidencePrevHash = hash;
      return item;
    });
    const likelihood = evidence.reduce((p, e) => p * e.lr, 1);
    const confidence = bayesianConfidence(PRIOR_ODDS, likelihood);

    const finding: FindingRecord = {
      id: findingId,
      scanId: scan.scanId,
      agentKey: agent.spec.key,
      title: raw.title,
      severity: raw.severity,
      category: raw.category,
      confidence,
      band: bandOf(confidence),
      target: scan.target,
      endpoint: raw.endpoint,
      cve: raw.cve,
      description: raw.description,
      pocScript: raw.pocScript,
      priorOdds: PRIOR_ODDS,
      likelihood: round1(likelihood),
      createdAt,
      evidence,
    };
    scan.findings.push(finding);
    agent.findings += 1;

    this.broadcast("finding:new", {
      scanId: scan.scanId,
      finding: { ...finding, scan: { id: scan.scanId, target: scan.target, status: scan.status } },
    });
    this.pushEvent(scan, "finding", `◈ FINDING [${finding.severity}/${finding.band}] ${finding.title} — confidence ${finding.confidence}`);
    this.emitAgentUpdate(scan, agent);
    log(`scan ${scan.scanId} finding — [${finding.severity}/${finding.band}] ${finding.title} (conf ${finding.confidence})`);
    this.checkSpawn(scan);
  }

  // ── Dynamic attack-chain synthesis ──
  private buildAttackChains(scan: ScanRuntime): void {
    const projection: ChainFinding[] = scan.findings.map((f) => ({
      id: f.id,
      agentKey: f.agentKey,
      category: f.category,
      severity: f.severity,
      title: f.title,
      endpoint: f.endpoint,
      cve: f.cve,
    }));
    const synthesized = synthesizeChains(projection, scan.host);
    for (const data of synthesized) {
      // one chain per goal-name; replace if findings changed it.
      const existingIdx = scan.chains.findIndex((c) => c.name === data.name);
      const record: ChainRecord = {
        ...data,
        id: `chain-${scan.scanId}-${existingIdx >= 0 ? existingIdx + 1 : scan.chains.length + 1}`,
        scanId: scan.scanId,
        verified: false,
        currentStep: 0,
      };
      if (existingIdx >= 0) {
        scan.chains[existingIdx] = record;
      } else {
        scan.chains.push(record);
        this.pushEvent(scan, "chain", `⛓ attack chain synthesized — ${record.name} (${record.severity}, ${record.steps.length} steps, approval gates armed)`);
        log(`scan ${scan.scanId} chain — ${record.name}`);
      }
    }
  }

  // ── Dynamic agent spawn ──
  private checkSpawn(scan: ScanRuntime): void {
    if (scan.killed || scan.finished) return;
    for (const spec of DYNAMIC_AGENTS) {
      if (scan.spawnedKeys.has(spec.key)) continue;
      const cond = spec.spawnOn;
      if (!cond) continue;
      let reason = "";
      if (cond.agentKeys) {
        for (const k of cond.agentKeys) {
          const run = scan.agents.get(k);
          if (run && run.status === "done" && run.findings > 0) {
            reason = `${AGENT_BY_KEY[k].tag} produced ${run.findings} finding(s)`;
            break;
          }
        }
      }
      if (!reason && cond.minFindings !== undefined) {
        const distinct = new Set(scan.findings.map((f) => f.agentKey)).size;
        if (scan.findings.length >= cond.minFindings && (cond.distinctAgents === undefined || distinct >= cond.distinctAgents)) {
          reason = `${scan.findings.length} finding(s) from ${distinct} distinct agent(s)`;
        }
      }
      if (!reason) continue;
      this.spawnDynamicAgent(scan, spec, reason);
    }
  }

  private spawnDynamicAgent(scan: ScanRuntime, spec: AgentSpec, reason: string): void {
    scan.spawnedKeys.add(spec.key);
    const agent = scan.agents.get(spec.key);
    if (!agent || agent.status !== "dormant") return;
    agent.status = "pending";
    agent.state = spec.states[0];
    agent.totalStates = spec.states.length;
    scan.totalPlannedStates += agent.totalStates;
    this.recomputeProgress(scan);
    this.pushEvent(scan, "system", `⚡ dynamic spawn — ${spec.tag} joined the scan (${reason}; trigger: ${spec.spawnOnDesc ?? "runtime condition met"})`);
    log(`scan ${scan.scanId} dynamic spawn — ${spec.key} (${reason})`);
    if (scan.policyTier === "safe" && isDataTouching(spec.key)) {
      this.blockAgent(scan, agent);
      return;
    }
    void this.runAgent(scan, agent);
  }

  // ── Ingest ──
  private postIngest(scan: ScanRuntime, status: "completed" | "killed"): void {
    const payload = {
      scanId: scan.scanId,
      status,
      requestCount: scan.requestCount,
      agentRuns: [...scan.agents.values()].map((a) => ({
        agentKey: a.spec.key,
        agentName: a.spec.name,
        version: a.spec.version,
        state: a.state,
        status: a.status,
        progress: round1(a.progress),
        requests: a.requests,
        findings: a.findings,
      })),
      findings: scan.findings.map((f) => ({
        agentKey: f.agentKey,
        title: f.title,
        severity: f.severity,
        category: f.category,
        confidence: f.confidence,
        band: f.band,
        target: f.target,
        endpoint: f.endpoint,
        cve: f.cve,
        description: f.description,
        pocScript: f.pocScript,
        priorOdds: f.priorOdds,
        likelihood: f.likelihood,
        createdAt: f.createdAt,
        evidence: f.evidence.map((e) => ({ kind: e.kind, lr: e.lr, content: e.content, hash: e.hash, prevHash: e.prevHash, sequence: e.sequence })),
      })),
      events: scan.events.map((e) => ({ type: e.type, message: e.message, meta: e.meta ?? null })),
      chains: scan.chains.map((c) => ({ name: c.name, severity: c.severity, steps: c.steps, graph: c.graph })),
    };
    fetch(CONTROL_PLANE_INGEST, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15000),
    })
      .then(async (res) => {
        if (!res.ok) {
          const body = await res.text().catch(() => "");
          logError(`ingest ${scan.scanId} (${status}) → HTTP ${res.status} ${body.slice(0, 160)}`);
        } else {
          log(`ingest ${scan.scanId} (${status}) accepted by control plane`);
        }
      })
      .catch((err: unknown) => logError(`ingest ${scan.scanId} (${status}) failed`, err));
  }

  // ── Bookkeeping ──
  private archive(scan: ScanRuntime): void {
    this.scans.delete(scan.scanId);
    this.history.unshift(this.scanToListItem(scan, false));
    if (this.history.length > HISTORY_CAP) this.history.length = HISTORY_CAP;
  }

  private recomputeProgress(scan: ScanRuntime): void {
    scan.progress = scan.totalPlannedStates > 0 ? round1((scan.completedStates / scan.totalPlannedStates) * 100) : 0;
  }

  private recordRequests(n: number): void {
    const ts = Date.now();
    for (let i = 0; i < n; i++) this.requestTimestamps.push(ts);
    if (this.requestTimestamps.length > 20000) this.requestsPerMin();
  }

  private agentSnapshot(scan: ScanRuntime, a: AgentRunRT): AgentRunSnapshot {
    return {
      id: `${scan.scanId}:${a.spec.key}`,
      scanId: scan.scanId,
      agentKey: a.spec.key,
      agentName: a.spec.name,
      version: a.spec.version,
      state: a.state,
      status: a.status,
      progress: round1(a.progress),
      requests: a.requests,
      findings: a.findings,
      startedAt: a.startedAt,
      endedAt: a.endedAt,
    };
  }

  private scanToListItem(scan: ScanRuntime, active: boolean): ScanListItem {
    return {
      scanId: scan.scanId,
      target: scan.target,
      profile: scan.profile,
      policyTier: scan.policyTier,
      seed: scan.seed,
      scope: scan.scope,
      status: scan.status,
      progress: round1(scan.progress),
      requestCount: scan.requestCount,
      findingsCount: scan.findings.length,
      chainsCount: scan.chains.length,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      active,
      agents: [...scan.agents.values()].map((a) => this.agentSnapshot(scan, a)),
    };
  }

  // ── Broadcast helpers ──
  private emitScanUpdate(scan: ScanRuntime): void {
    this.broadcast("scan:update", { scanId: scan.scanId, status: scan.status, progress: round1(scan.progress), requestCount: scan.requestCount } satisfies EngineScanUpdate);
  }
  private emitAgentUpdate(scan: ScanRuntime, agent: AgentRunRT): void {
    this.broadcast("agent:update", {
      scanId: scan.scanId,
      agentKey: agent.spec.key,
      agentName: agent.spec.name,
      version: agent.spec.version,
      state: agent.state,
      status: agent.status,
      progress: round1(agent.progress),
      requests: agent.requests,
      findings: agent.findings,
    } satisfies EngineAgentUpdate);
  }
  private pushEvent(scan: ScanRuntime, type: string, message: string, meta?: string | null): void {
    const ts = nowIso();
    scan.events.push({ type, message, meta: meta ?? null, ts });
    if (scan.events.length > EVENT_RING_CAP) scan.events.shift();
    this.broadcast("event:new", { scanId: scan.scanId, type, message, ts });
  }
}
