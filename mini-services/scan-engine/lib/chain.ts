// ─── Dynamic attack-chain synthesis ─────────────────────────────────────────
//
// NodeZero-style: nothing about a chain is predefined. Paths are assembled at
// runtime from whatever findings the scan actually produced. Findings are
// bucketed by the capability they grant an attacker (entry → access →
// escalation → impact); a goal with a qualifying finding becomes a chain whose
// steps are concrete, SAFE proof-of-access verifications — never destructive
// actions. If no findings compose into a path, no chain is emitted.

import type { Severity } from "./findings";
import { SEVERITY_RANK } from "./findings";

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
  x?: number;
  y?: number;
}

export interface ChainGraphEdge {
  from: string;
  to: string;
  label: string;
}

export interface ChainData {
  name: string;
  severity: Severity;
  steps: ChainStep[];
  graph: { nodes: ChainGraphNode[]; edges: ChainGraphEdge[] };
}

/** Minimal finding projection the synthesizer reasons over. */
export interface ChainFinding {
  id: string;
  agentKey: string;
  category: string;
  severity: Severity;
  title: string;
  endpoint: string | null;
  cve: string | null;
}

type Goal = {
  id: string;
  name: (host: string) => string;
  /** which findings qualify as a step toward this goal */
  match: (f: ChainFinding) => boolean;
  /** the terminal impact node this goal reaches */
  impact: string;
  impactDetail: string;
};

// Attack goals, evaluated against the live findings board. Category/agent
// membership — not a fixed template — decides which findings compose a path.
const GOALS: Goal[] = [
  {
    id: "rce",
    name: (h) => `Remote code execution path on ${h}`,
    match: (f) =>
      ["injection", "deser", "fileops", "prototype", "smuggling", "edge"].includes(f.agentKey) ||
      /rce|injection|deserial|traversal|code-exec|template/i.test(f.category + " " + f.title),
    impact: "Code execution / host compromise",
    impactDetail: "attacker-controlled code runs in the application context",
  },
  {
    id: "creds",
    name: (h) => `Credential & data exposure path on ${h}`,
    match: (f) =>
      ["secrets", "gitrepo", "auth", "saml"].includes(f.agentKey) ||
      /secret|disclosure|credential|token|key|idor|auth/i.test(f.category + " " + f.title),
    impact: "Sensitive data / account access",
    impactDetail: "leaked credentials or broken authz grant access to data and accounts",
  },
  {
    id: "pivot",
    name: (h) => `Internal pivot path from ${h}`,
    match: (f) =>
      ["ssrf", "cloud", "pivot"].includes(f.agentKey) ||
      /ssrf|metadata|imds|internal|pivot|bucket/i.test(f.category + " " + f.title),
    impact: "Internal network / cloud control plane",
    impactDetail: "server-side request forgery or cloud misconfig reaches internal-only surfaces",
  },
  {
    id: "exposure",
    name: (h) => `Exposed-service compromise path on ${h}`,
    match: (f) =>
      f.category === "exposure" || /exposed|open port|unauth|database|rdp|smb|redis|mongo/i.test(f.category + " " + f.title),
    impact: "Direct service takeover",
    impactDetail: "an exposed management/data-plane service is reachable without the app",
  },
];

function maxSeverity(sevs: Severity[]): Severity {
  let best: Severity = "info";
  for (const s of sevs) if (SEVERITY_RANK[s] > SEVERITY_RANK[best]) best = s;
  return best;
}

/**
 * Build every chain supported by the findings. Each qualifying goal yields one
 * chain: entry → (each contributing finding, severity-ordered) → impact.
 */
export function synthesizeChains(findings: ChainFinding[], host: string): ChainData[] {
  const chains: ChainData[] = [];
  const bySeverity = (a: ChainFinding, b: ChainFinding) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];

  for (const goal of GOALS) {
    const contributing = findings.filter(goal.match).sort(bySeverity);
    if (contributing.length === 0) continue;
    // Require at least one non-info finding — info-only is reconnaissance, not a path.
    if (!contributing.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK["low"])) continue;

    const nodes: ChainGraphNode[] = [];
    const edges: ChainGraphEdge[] = [];
    const steps: ChainStep[] = [];

    const entryId = "asset-entry";
    nodes.push({ id: entryId, label: host, type: "asset", x: 8, y: 50, detail: "engagement entry point" });

    steps.push({
      title: "Confirm entry reachability",
      action: `Verify ${host} is reachable and in scope (read-only HEAD request)`,
      status: "pending",
      findingId: null,
    });

    const take = contributing.slice(0, 4);
    const ySpread = take.length > 1 ? 70 / (take.length - 1) : 0;
    take.forEach((f, i) => {
      const nodeId = `f-${f.id}`;
      const y = take.length > 1 ? 15 + i * ySpread : 50;
      const x = 32 + i * (36 / Math.max(1, take.length));
      nodes.push({
        id: nodeId,
        label: f.title.slice(0, 48),
        type: f.agentKey === "secrets" || f.agentKey === "auth" ? "credential" : "finding",
        severity: f.severity,
        x: Math.min(68, x),
        y,
        detail: f.cve ?? f.category,
      });
      edges.push({ from: i === 0 ? entryId : `f-${take[i - 1].id}`, to: nodeId, label: i === 0 ? "exposes" : "enables" });
      steps.push({
        title: `Verify: ${f.title.slice(0, 60)}`,
        action: f.endpoint
          ? `Proof-of-access check against ${f.endpoint} (${f.severity}${f.cve ? `, ${f.cve}` : ""}) — non-destructive`
          : `Re-verify ${f.title} (${f.severity}) — non-destructive`,
        status: "pending",
        findingId: f.id,
      });
    });

    const impactId = "impact";
    nodes.push({
      id: impactId,
      label: goal.impact,
      type: "impact",
      severity: maxSeverity(take.map((f) => f.severity)),
      x: 86,
      y: 50,
      detail: goal.impactDetail,
    });
    edges.push({ from: `f-${take[take.length - 1].id}`, to: impactId, label: "achieves" });

    steps.push({
      title: "Demonstrate impact (gated)",
      action: `Assemble proof-of-access for "${goal.impact}" behind the 4-eyes approval gate — no data destroyed or exfiltrated`,
      status: "pending",
      findingId: null,
    });

    chains.push({
      name: goal.name(host),
      severity: maxSeverity(take.map((f) => f.severity)),
      steps,
      graph: { nodes, edges },
    });
  }

  // Strongest chain first.
  return chains.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}
