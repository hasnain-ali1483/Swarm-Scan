import { NextResponse, type NextRequest } from "next/server";
import { buildSchema, graphqlSync, printSchema, type GraphQLError } from "graphql";
import type { AgentRun, AttackChain, Finding, Scan } from "@prisma/client";
import { db } from "@/lib/db";
import {
  SEVERITY_ORDER,
  type ChainStep,
  type ConfidenceBand,
  type GraphData,
  type GraphEdge,
  type GraphNode,
  type GraphStats,
  type GqlResponse,
  type Severity,
} from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

// ─── Schema (SDL → buildSchema, executed with graphqlSync) ───────────────────

const SDL = /* GraphQL */ `
  # SwarmScan output plane — the correlator's finding graph, queryable.
  type Query {
    graph(severity: String, band: String, scanId: String, agentKey: String, limit: Int): GraphData!
    findings(severity: String, band: String, agentKey: String, limit: Int): [FindingNode!]!
    scans(status: String, limit: Int): [ScanNode!]!
    stats: PlatformStats!
    node(id: ID!): Node
    schemaSDL: String!
  }

  type GraphNode {
    id: String!
    kind: String! # target | scan | agent | finding | chain
    label: String!
    sub: String!
    severity: String
    band: String
    status: String
  }

  type GraphEdge {
    id: String!
    source: String!
    target: String!
    kind: String! # scoped | executed | produced | correlated
  }

  type GraphStats {
    nodes: Int!
    edges: Int!
    targets: Int!
    scans: Int!
    agents: Int!
    findings: Int!
    chains: Int!
  }

  type GraphData {
    nodes: [GraphNode!]!
    edges: [GraphEdge!]!
    stats: GraphStats!
  }

  type FindingNode {
    id: String!
    label: String!
    severity: String!
    band: String!
    confidence: Float!
    agentKey: String!
    target: String!
    category: String!
  }

  type ScanNode {
    id: String!
    target: String!
    status: String!
    profile: String!
    findingCount: Int!
    requestCount: Int!
    startedAt: String
  }

  type PlatformStats {
    scans: Int!
    findings: Int!
    confirmed: Int!
    chains: Int!
    evidence: Int!
    avgConfidence: Float!
  }

  # Inspector drill-down: a GraphNode plus a prose detail blob.
  type Node {
    id: String!
    kind: String!
    label: String!
    sub: String!
    severity: String
    band: String
    status: String
    detail: String!
  }
`;

const schema = buildSchema(SDL);

// ─── Data source (prefetched — root resolvers are synchronous) ───────────────

interface GraphSource {
  scans: Scan[];
  runs: AgentRun[];
  findings: Finding[];
  chains: AttackChain[];
  chainSteps: Map<string, ChainStep[]>;
  evidenceCountByFinding: Map<string, number>;
  evidenceTotal: number;
}

async function loadSource(): Promise<GraphSource> {
  const [scans, runs, findings, chains, evidence] = await Promise.all([
    db.scan.findMany({ orderBy: { createdAt: "asc" } }),
    db.agentRun.findMany({ orderBy: [{ scanId: "asc" }, { agentKey: "asc" }] }),
    db.finding.findMany({ orderBy: { createdAt: "asc" } }),
    db.attackChain.findMany({ orderBy: { id: "asc" } }),
    db.evidence.findMany({ select: { findingId: true } }),
  ]);

  const chainSteps = new Map<string, ChainStep[]>();
  for (const c of chains) {
    let steps: ChainStep[] = [];
    try {
      steps = JSON.parse(c.steps) as ChainStep[];
    } catch {
      steps = [];
    }
    chainSteps.set(c.id, Array.isArray(steps) ? steps : []);
  }

  const evidenceCountByFinding = new Map<string, number>();
  for (const e of evidence) {
    if (e.findingId) {
      evidenceCountByFinding.set(e.findingId, (evidenceCountByFinding.get(e.findingId) ?? 0) + 1);
    }
  }

  return {
    scans,
    runs,
    findings,
    chains,
    chainSteps,
    evidenceCountByFinding,
    evidenceTotal: evidence.length,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hostOf(target: string): string {
  return target.replace(/^https?:\/\//, "");
}

function severityRank(severity: string): number {
  const idx = SEVERITY_ORDER.indexOf(severity as Severity);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

function iso(d: Date | null): string | null {
  return d ? d.toISOString() : null;
}

function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 10)}…` : id;
}

// Node ids are kind-prefixed so the explorer can route inspector drill-downs.
const T = (target: string) => `t:${target}`;
const S = (scanId: string) => `s:${scanId}`;
const A = (scanId: string, agentKey: string) => `a:${scanId}:${agentKey}`;
const F = (findingId: string) => `f:${findingId}`;
const C = (chainId: string) => `c:${chainId}`;

// ─── graph() — the core field ────────────────────────────────────────────────

interface GraphArgs {
  severity?: string | null;
  band?: string | null;
  scanId?: string | null;
  agentKey?: string | null;
  limit?: number | null;
}

function buildGraph(src: GraphSource, args: GraphArgs): GraphData {
  const cap = Math.min(200, Math.max(1, Math.floor(args.limit ?? 60)));

  const scans = args.scanId ? src.scans.filter((s) => s.id === args.scanId) : src.scans;
  const scanIds = new Set(scans.map((s) => s.id));

  // Findings: filtered, then capped (severity rank → confidence → date).
  const filteredFindings = src.findings
    .filter(
      (f) =>
        scanIds.has(f.scanId) &&
        (!args.severity || f.severity === args.severity) &&
        (!args.band || f.band === args.band) &&
        (!args.agentKey || f.agentKey === args.agentKey),
    )
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        b.confidence - a.confidence ||
        a.createdAt.getTime() - b.createdAt.getTime(),
    )
    .slice(0, cap);
  const findingIds = new Set(filteredFindings.map((f) => f.id));

  // Agent runs within the scan scope (and agent subgraph filter).
  const runs = src.runs.filter(
    (r) => scanIds.has(r.scanId) && (!args.agentKey || r.agentKey === args.agentKey),
  );
  const agentNodeIds = new Set(runs.map((r) => A(r.scanId, r.agentKey)));

  // Unfiltered per-scan / per-target totals for the node captions.
  const findingsPerScan = new Map<string, number>();
  for (const f of src.findings) {
    findingsPerScan.set(f.scanId, (findingsPerScan.get(f.scanId) ?? 0) + 1);
  }
  const findingsPerTarget = new Map<string, number>();
  for (const f of src.findings) {
    findingsPerTarget.set(f.target, (findingsPerTarget.get(f.target) ?? 0) + 1);
  }

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // Target + scan nodes, scoped edges (target → scan).
  const seenTargets = new Set<string>();
  for (const scan of scans) {
    const tId = T(scan.target);
    if (!seenTargets.has(tId)) {
      seenTargets.add(tId);
      const targetScanCount = src.scans.filter((s) => s.target === scan.target).length;
      nodes.push({
        id: tId,
        kind: "target",
        label: hostOf(scan.target),
        sub: `${targetScanCount} scans · ${findingsPerTarget.get(scan.target) ?? 0} findings`,
      });
    }
    edges.push({ id: `e:${tId}->${S(scan.id)}`, source: tId, target: S(scan.id), kind: "scoped" });
    nodes.push({
      id: S(scan.id),
      kind: "scan",
      label: `${scan.profile} · ${hostOf(scan.target)}`,
      sub: `${findingsPerScan.get(scan.id) ?? 0} findings · ${scan.requestCount} reqs`,
      status: scan.status,
    });
  }

  // Agent nodes, executed edges (scan → agent).
  for (const run of runs) {
    const agentId = A(run.scanId, run.agentKey);
    edges.push({
      id: `e:${S(run.scanId)}->${agentId}`,
      source: S(run.scanId),
      target: agentId,
      kind: "executed",
    });
    nodes.push({
      id: agentId,
      kind: "agent",
      label: run.agentKey,
      sub: `${run.agentName} · v${run.version} · ${run.findings} findings`,
      status: run.status,
    });
  }

  // Finding nodes, produced edges (agent → finding, severity-colored upstream).
  for (const f of filteredFindings) {
    const agentId = A(f.scanId, f.agentKey);
    if (agentNodeIds.has(agentId)) {
      edges.push({ id: `e:${agentId}->${F(f.id)}`, source: agentId, target: F(f.id), kind: "produced" });
    }
    nodes.push({
      id: F(f.id),
      kind: "finding",
      label: f.title,
      sub: `${f.band} · ${f.confidence}% conf`,
      severity: f.severity as Severity,
      band: f.band as ConfidenceBand,
    });
  }

  // Chain nodes + correlated edges (finding → chain, via step findingIds).
  const chains = src.chains.filter((c) => scanIds.has(c.scanId));
  const seenCorrelated = new Set<string>();
  for (const chain of chains) {
    const steps = src.chainSteps.get(chain.id) ?? [];
    const executedSteps = steps.filter((s) => s.status === "executed").length;
    nodes.push({
      id: C(chain.id),
      kind: "chain",
      label: chain.name,
      sub: `${executedSteps}/${steps.length} steps${chain.verified ? " · verified" : ""}`,
      severity: chain.severity as Severity,
    });
    for (const step of steps) {
      if (step.findingId && findingIds.has(step.findingId)) {
        const key = `${C(chain.id)}:${step.findingId}`;
        if (seenCorrelated.has(key)) continue;
        seenCorrelated.add(key);
        edges.push({
          id: `e:${F(step.findingId)}->${C(chain.id)}`,
          source: F(step.findingId),
          target: C(chain.id),
          kind: "correlated",
        });
      }
    }
  }

  // Prune disconnected nodes (chains with no surviving correlated findings).
  const degree = new Map<string, number>();
  for (const n of nodes) degree.set(n.id, 0);
  for (const e of edges) {
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }
  const keptNodes = nodes.filter((n) => (degree.get(n.id) ?? 0) > 0);
  const keptIds = new Set(keptNodes.map((n) => n.id));
  const keptEdges = edges.filter((e) => keptIds.has(e.source) && keptIds.has(e.target));

  const stats: GraphStats = {
    nodes: keptNodes.length,
    edges: keptEdges.length,
    targets: keptNodes.filter((n) => n.kind === "target").length,
    scans: keptNodes.filter((n) => n.kind === "scan").length,
    agents: keptNodes.filter((n) => n.kind === "agent").length,
    findings: keptNodes.filter((n) => n.kind === "finding").length,
    chains: keptNodes.filter((n) => n.kind === "chain").length,
  };

  return { nodes: keptNodes, edges: keptEdges, stats };
}

// ─── node(id) — inspector drill-down ─────────────────────────────────────────

interface NodeDetail extends GraphNode {
  detail: string;
}

function nodeDetail(src: GraphSource, id: string): NodeDetail | null {
  if (id.startsWith("t:")) {
    const target = id.slice(2);
    const targetScans = src.scans.filter((s) => s.target === target);
    if (targetScans.length === 0) return null;
    const scanIds = new Set(targetScans.map((s) => s.id));
    const targetFindings = src.findings.filter((f) => f.target === target);
    const crit = targetFindings.filter((f) => f.severity === "critical").length;
    const high = targetFindings.filter((f) => f.severity === "high").length;
    const med = targetFindings.filter((f) => f.severity === "medium").length;
    const runs = src.runs.filter((r) => scanIds.has(r.scanId)).length;
    const chains = src.chains.filter((c) => scanIds.has(c.scanId)).length;
    const completed = targetScans.filter((s) => s.status === "completed").length;
    return {
      id,
      kind: "target",
      label: hostOf(target),
      sub: `${targetScans.length} scans · ${targetFindings.length} findings`,
      detail:
        `Target scanned ${targetScans.length} times (${completed} completed) across ${runs} agent runs. ` +
        `Findings to date: ${targetFindings.length} (${crit} critical, ${high} high, ${med} medium). ` +
        `Correlated attack chains: ${chains}. First seen ${iso(targetScans[0].createdAt)}.`,
    };
  }

  if (id.startsWith("s:")) {
    const scan = src.scans.find((s) => s.id === id.slice(2));
    if (!scan) return null;
    const scanFindings = src.findings.filter((f) => f.scanId === scan.id);
    const crit = scanFindings.filter((f) => f.severity === "critical").length;
    const high = scanFindings.filter((f) => f.severity === "high").length;
    const chains = src.chains.filter((c) => c.scanId === scan.id);
    const runs = src.runs.filter((r) => r.scanId === scan.id);
    return {
      id,
      kind: "scan",
      label: `${scan.profile} · ${hostOf(scan.target)}`,
      sub: `${scanFindings.length} findings · ${scan.requestCount} reqs`,
      status: scan.status,
      detail:
        `${scan.profile} profile scan of ${scan.target} — status ${scan.status}. Policy tier ${scan.policyTier}, seed ${scan.seed}. ` +
        `${scan.requestCount} requests across ${scan.agentCount} agents (${runs.length} runs recorded). ` +
        `${scanFindings.length} findings produced (${crit} critical, ${high} high), ${chains.length} attack chains correlated. ` +
        `Started ${iso(scan.startedAt) ?? "—"}.`,
    };
  }

  if (id.startsWith("a:")) {
    const rest = id.slice(2);
    const sep = rest.indexOf(":");
    if (sep === -1) return null;
    const run = src.runs.find((r) => r.scanId === rest.slice(0, sep) && r.agentKey === rest.slice(sep + 1));
    if (!run) return null;
    const scan = src.scans.find((s) => s.id === run.scanId);
    return {
      id,
      kind: "agent",
      label: run.agentKey,
      sub: `${run.agentName} · v${run.version} · ${run.findings} findings`,
      status: run.status,
      detail:
        `${run.agentName} (${run.agentKey}) v${run.version} executed on ${scan ? scan.target : run.scanId}. ` +
        `FSM state "${run.state}", run status ${run.status}. ${run.requests} requests issued, ${run.findings} findings produced. ` +
        `Started ${iso(run.startedAt) ?? "—"}, ended ${iso(run.endedAt) ?? "—"}.`,
    };
  }

  if (id.startsWith("f:")) {
    const finding = src.findings.find((f) => f.id === id.slice(2));
    if (!finding) return null;
    const evidenceCount = src.evidenceCountByFinding.get(finding.id) ?? 0;
    return {
      id,
      kind: "finding",
      label: finding.title,
      sub: `${finding.band} · ${finding.confidence}% conf`,
      severity: finding.severity as Severity,
      band: finding.band as ConfidenceBand,
      detail:
        `${finding.title}. ${finding.severity}/${finding.band} finding by ${finding.agentKey} on ${finding.target}` +
        `${finding.endpoint ? ` at ${finding.endpoint}` : ""}. ` +
        `Bayesian confidence ${finding.confidence}% (prior odds ${finding.priorOdds}, ∏LR ${finding.likelihood}) ` +
        `backed by ${evidenceCount} hash-chained evidence items${finding.cve ? ` · ${finding.cve}` : ""}. ` +
        `${finding.description} Detected ${iso(finding.createdAt)}.`,
    };
  }

  if (id.startsWith("c:")) {
    const chain = src.chains.find((c) => c.id === id.slice(2));
    if (!chain) return null;
    const steps = src.chainSteps.get(chain.id) ?? [];
    const executed = steps.filter((s) => s.status === "executed").length;
    const scan = src.scans.find((s) => s.id === chain.scanId);
    return {
      id,
      kind: "chain",
      label: chain.name,
      sub: `${executed}/${steps.length} steps${chain.verified ? " · verified" : ""}`,
      severity: chain.severity as Severity,
      detail:
        `Correlator chain "${chain.name}" (${chain.severity}) on ${scan ? scan.target : chain.scanId} — ` +
        `${chain.verified ? "fully verified" : `step ${chain.currentStep + 1} of ${steps.length} pending approval`}. ` +
        `Steps: ${steps.map((s, i) => `${i + 1}. ${s.title} [${s.status}]`).join(" → ")}. ` +
        `Chain id ${shortId(chain.id)}.`,
    };
  }

  return null;
}

// ─── Root value (synchronous resolvers over the prefetched source) ───────────

interface FindingsArgs {
  severity?: string | null;
  band?: string | null;
  agentKey?: string | null;
  limit?: number | null;
}

interface ScansArgs {
  status?: string | null;
  limit?: number | null;
}

function makeRoot(src: GraphSource) {
  return {
    graph: (args: GraphArgs) => buildGraph(src, args),
    findings: (args: FindingsArgs) => {
      const cap = Math.min(200, Math.max(1, Math.floor(args.limit ?? 60)));
      return src.findings
        .filter(
          (f) =>
            (!args.severity || f.severity === args.severity) &&
            (!args.band || f.band === args.band) &&
            (!args.agentKey || f.agentKey === args.agentKey),
        )
        .sort(
          (a, b) =>
            severityRank(a.severity) - severityRank(b.severity) ||
            b.confidence - a.confidence ||
            a.createdAt.getTime() - b.createdAt.getTime(),
        )
        .slice(0, cap)
        .map((f) => ({
          id: f.id,
          label: f.title,
          severity: f.severity,
          band: f.band,
          confidence: f.confidence,
          agentKey: f.agentKey,
          target: f.target,
          category: f.category,
        }));
    },
    scans: (args: ScansArgs) => {
      const cap = Math.min(100, Math.max(1, Math.floor(args.limit ?? 25)));
      const findingsPerScan = new Map<string, number>();
      for (const f of src.findings) {
        findingsPerScan.set(f.scanId, (findingsPerScan.get(f.scanId) ?? 0) + 1);
      }
      return src.scans
        .filter((s) => !args.status || s.status === args.status)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
        .slice(0, cap)
        .map((s) => ({
          id: s.id,
          target: s.target,
          status: s.status,
          profile: s.profile,
          findingCount: findingsPerScan.get(s.id) ?? 0,
          requestCount: s.requestCount,
          startedAt: iso(s.startedAt),
        }));
    },
    stats: () => {
      const confirmed = src.findings.filter((f) => f.band === "confirmed").length;
      const avg =
        src.findings.length > 0
          ? Math.round((src.findings.reduce((a, f) => a + f.confidence, 0) / src.findings.length) * 10) / 10
          : 0;
      return {
        scans: src.scans.length,
        findings: src.findings.length,
        confirmed,
        chains: src.chains.length,
        evidence: src.evidenceTotal,
        avgConfidence: avg,
      };
    },
    node: (args: { id: string }) => nodeDetail(src, args.id),
    schemaSDL: () => printSchema(schema),
  };
}

// ─── Route handlers ──────────────────────────────────────────────────────────

function serializeGqlError(
  e: GraphQLError,
): { message: string; locations?: { line: number; column: number }[] } {
  const locations = e.locations?.map((l) => ({ line: l.line, column: l.column }));
  return locations && locations.length > 0 ? { message: e.message, locations } : { message: e.message };
}

/** GET /api/graphql — printed SDL for the docs panel. */
export async function GET() {
  try {
    return NextResponse.json({ sdl: printSchema(schema) });
  } catch (err) {
    console.error("[api/graphql] GET failed", err);
    return NextResponse.json({ error: "Failed to print schema" }, { status: 500 });
  }
}

/** POST /api/graphql — { query, variables? } → GqlResponse { data, errors, latencyMs }. */
export async function POST(req: NextRequest) {
  try {
    let body: unknown = null;
    try {
      body = await req.json();
    } catch {
      body = null;
    }
    const rawQuery = (body as { query?: unknown } | null)?.query;
    if (typeof rawQuery !== "string" || rawQuery.trim().length === 0) {
      return NextResponse.json(
        { error: "Missing GraphQL query — POST body must be JSON { query, variables? }" },
        { status: 400 },
      );
    }
    const rawVars = (body as { variables?: unknown } | null)?.variables;
    const variableValues =
      rawVars && typeof rawVars === "object" && !Array.isArray(rawVars)
        ? (rawVars as Record<string, unknown>)
        : undefined;

    const t0 = performance.now();
    const src = await loadSource();
    const root = makeRoot(src);
    const result = graphqlSync({
      schema,
      source: rawQuery,
      rootValue: root,
      variableValues,
    });
    const latencyMs = Math.round((performance.now() - t0) * 10) / 10;

    const payload: GqlResponse = {
      ...(result.data !== undefined ? { data: result.data } : {}),
      ...(result.errors && result.errors.length > 0
        ? { errors: result.errors.map(serializeGqlError) }
        : {}),
      latencyMs,
    };
    return NextResponse.json(payload);
  } catch (err) {
    console.error("[api/graphql] POST failed", err);
    return NextResponse.json({ error: "GraphQL execution failed" }, { status: 500 });
  }
}
