// ─── Prisma row → API JSON shape mappers (single source for the control plane) ──

import type {
  AgentRun as AgentRunRow,
  AttackChain as AttackChainRow,
  Evidence as EvidenceRow,
  EventLog as EventLogRow,
  Finding as FindingRow,
  Policy as PolicyRow,
  Scan as ScanRow,
  ScopeRule as ScopeRuleRow,
  Target as TargetRow,
} from "@prisma/client";
import type {
  AgentRun,
  AttackChainItem,
  ChainGraphEdge,
  ChainGraphNode,
  ChainStep,
  ConfidenceBand,
  EvidenceItem,
  EvidenceKind,
  EventLogItem,
  Finding,
  PolicyItem,
  ScanProfile,
  ScanStatus,
  ScanSummary,
  ScopeRuleItem,
  Severity,
  TargetItem,
} from "@/lib/swarm/types";

export type FindingRowFull = FindingRow & {
  evidence?: EvidenceRow[];
  scan?: { id: string; target: string; status: string } | null;
};

export type ScanRowWithCounts = ScanRow & {
  findingsCount?: number;
  findingsBySeverity?: Record<string, number>;
};

function iso(d: Date | null | undefined): string | null {
  return d ? d.toISOString() : null;
}

export function serializeEvidence(e: EvidenceRow): EvidenceItem {
  return {
    id: e.id,
    findingId: e.findingId,
    scanId: e.scanId,
    kind: e.kind as EvidenceKind,
    lr: e.lr,
    content: e.content,
    hash: e.hash,
    prevHash: e.prevHash,
    sequence: e.sequence,
    createdAt: e.createdAt.toISOString(),
  };
}

export function serializeFinding(f: FindingRowFull): Finding {
  return {
    id: f.id,
    scanId: f.scanId,
    agentKey: f.agentKey,
    title: f.title,
    severity: f.severity as Severity,
    category: f.category,
    confidence: f.confidence,
    band: f.band as ConfidenceBand,
    target: f.target,
    endpoint: f.endpoint,
    cve: f.cve,
    description: f.description,
    pocScript: f.pocScript,
    priorOdds: f.priorOdds,
    likelihood: f.likelihood,
    createdAt: f.createdAt.toISOString(),
    ...(f.evidence
      ? { evidence: [...f.evidence].sort((a, b) => a.sequence - b.sequence).map(serializeEvidence) }
      : {}),
    ...(f.scan ? { scan: { id: f.scan.id, target: f.scan.target, status: f.scan.status } } : {}),
  };
}

export function serializeAgentRun(a: AgentRunRow): AgentRun {
  return {
    id: a.id,
    scanId: a.scanId,
    agentKey: a.agentKey,
    agentName: a.agentName,
    version: a.version,
    state: a.state,
    status: a.status as AgentRun["status"],
    progress: a.progress,
    requests: a.requests,
    findings: a.findings,
    startedAt: iso(a.startedAt),
    endedAt: iso(a.endedAt),
  };
}

export function serializeScan(s: ScanRowWithCounts): ScanSummary {
  return {
    id: s.id,
    target: s.target,
    profile: s.profile as ScanProfile,
    scope: (s.scope as ScanSummary["scope"]) ?? "external",
    status: s.status as ScanStatus,
    seed: s.seed,
    policyTier: s.policyTier as ScanSummary["policyTier"],
    progress: s.progress,
    requestCount: s.requestCount,
    agentCount: s.agentCount,
    startedAt: iso(s.startedAt),
    completedAt: iso(s.completedAt),
    createdAt: s.createdAt.toISOString(),
    ...(s.findingsCount !== undefined ? { findingsCount: s.findingsCount } : {}),
    ...(s.findingsBySeverity !== undefined ? { findingsBySeverity: s.findingsBySeverity } : {}),
  };
}

export function serializeTarget(t: TargetRow): TargetItem {
  return {
    id: t.id,
    name: t.name,
    value: t.value,
    scope: t.scope as TargetItem["scope"],
    environment: (t.environment as TargetItem["environment"]) ?? "external",
    kind: t.kind as TargetItem["kind"],
    authorized: t.authorized,
    attestedBy: t.attestedBy,
    attestedAt: iso(t.attestedAt),
    note: t.note,
    createdAt: t.createdAt.toISOString(),
  };
}

export function serializeEvent(e: EventLogRow): EventLogItem {
  return {
    id: e.id,
    scanId: e.scanId,
    type: e.type,
    message: e.message,
    meta: e.meta,
    createdAt: e.createdAt.toISOString(),
  };
}

function parseJsonSafe<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function serializeChain(c: AttackChainRow): AttackChainItem {
  return {
    id: c.id,
    scanId: c.scanId,
    name: c.name,
    severity: c.severity as Severity,
    verified: c.verified,
    currentStep: c.currentStep,
    steps: parseJsonSafe<ChainStep[]>(c.steps, []),
    graph: parseJsonSafe<{ nodes: ChainGraphNode[]; edges: ChainGraphEdge[] }>(c.graph, {
      nodes: [],
      edges: [],
    }),
  };
}

export function serializePolicy(p: PolicyRow): PolicyItem {
  return {
    id: p.id,
    name: p.name,
    kind: p.kind,
    code: p.code,
    enabled: p.enabled,
    updatedAt: p.updatedAt.toISOString(),
  };
}

export function serializeScopeRule(r: ScopeRuleRow): ScopeRuleItem {
  return {
    id: r.id,
    name: r.name,
    cidrs: parseJsonSafe<string[]>(r.cidrs, []),
    mode: r.mode as ScopeRuleItem["mode"],
    enforced: r.enforced,
  };
}
