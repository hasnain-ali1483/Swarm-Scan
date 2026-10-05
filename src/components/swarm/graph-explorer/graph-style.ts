// ─── Shared visual constants for the finding-graph explorer ──────────────────
// Dark SOC palette: emerald primary, zinc surfaces, severity accents.
// (No blue/indigo — low findings use lime, info uses zinc.)

import type { GraphNodeKind, Severity } from "@/lib/swarm/types";

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#dc2626", // red-600
  high: "#f97316", // orange-500
  medium: "#fbbf24", // amber-400
  low: "#84cc16", // lime-500
  info: "#a1a1aa", // zinc-500
};

export function severityColor(severity?: string | null): string {
  return SEVERITY_COLORS[(severity ?? "info") as Severity] ?? "#a1a1aa";
}

export const KIND_BASE_RADIUS: Record<GraphNodeKind, number> = {
  target: 15,
  scan: 9,
  agent: 7,
  finding: 6.5,
  chain: 11,
};

export const KIND_LABELS: Record<GraphNodeKind, string> = {
  target: "Target",
  scan: "Scan",
  agent: "Agent",
  finding: "Finding",
  chain: "Attack chain",
};

/** Agent-run status → stroke color for hexagons. */
export function agentStatusColor(status?: string | null): string {
  switch (status) {
    case "done":
      return "#34d399";
    case "running":
      return "#fbbf24";
    case "blocked":
      return "#f59e0b";
    case "killed":
      return "#ef4444";
    default:
      return "#71717a";
  }
}

/** Scan status → stroke color for scan circles. */
export function scanStatusColor(status?: string | null): string {
  switch (status) {
    case "completed":
      return "#10b981";
    case "running":
    case "verifying":
      return "#f59e0b";
    case "killed":
    case "failed":
      return "#ef4444";
    default:
      return "#71717a";
  }
}

export function hexPoints(r: number): string {
  const pts: string[] = [];
  for (let k = 0; k < 6; k++) {
    const a = (Math.PI / 3) * k - Math.PI / 6;
    pts.push(`${(r * Math.cos(a)).toFixed(2)},${(r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(" ");
}

export function truncateLabel(s: string, max = 16): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
