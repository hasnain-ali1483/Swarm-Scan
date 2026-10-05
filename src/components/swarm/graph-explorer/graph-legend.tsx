"use client";

// ─── Legend + graph stats chips (Task 9-a) ───────────────────────────────────
// Node kinds (mini shape glyphs), edge kinds (stroke samples), severity colors,
// and live counts from the current GraphData.stats.

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { GraphStats, GraphNodeKind } from "@/lib/swarm/types";
import { SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import { hexPoints } from "./graph-style";

const NODE_KINDS: { kind: GraphNodeKind; hint: string; shape: React.ReactNode }[] = [
  {
    kind: "target",
    hint: "scanned origin",
    shape: (
      <svg width="18" height="18" viewBox="-9 -9 18 18" aria-hidden>
        <rect x={-7} y={-7} width={14} height={14} rx={3} fill="#0c0c0e" stroke="#34d399" strokeWidth={1.4} />
        <rect x={-3} y={-3.5} width={6} height={3} rx={1} fill="none" stroke="#34d399" strokeWidth={0.9} />
        <rect x={-3} y={0.5} width={6} height={3} rx={1} fill="none" stroke="#34d399" strokeWidth={0.9} />
      </svg>
    ),
  },
  {
    kind: "scan",
    hint: "DAG scan plan",
    shape: (
      <svg width="18" height="18" viewBox="-9 -9 18 18" aria-hidden>
        <circle r={7} fill="#101013" stroke="#10b981" strokeWidth={1.4} />
      </svg>
    ),
  },
  {
    kind: "agent",
    hint: "agent run (hex)",
    shape: (
      <svg width="18" height="18" viewBox="-9 -9 18 18" aria-hidden>
        <polygon points={hexPoints(7)} fill="#0c0c0e" stroke="#34d399" strokeWidth={1.2} />
      </svg>
    ),
  },
  {
    kind: "finding",
    hint: "severity-colored",
    shape: (
      <svg width="18" height="18" viewBox="-9 -9 18 18" aria-hidden>
        <circle r={6.5} fill="#dc2626" fillOpacity={0.3} stroke="#dc2626" strokeWidth={1.6} />
      </svg>
    ),
  },
  {
    kind: "chain",
    hint: "correlated chain",
    shape: (
      <svg width="18" height="18" viewBox="-9 -9 18 18" aria-hidden>
        <polygon points="0,-7 7,0 0,7 -7,0" fill="#0c0c0e" stroke="#34d399" strokeWidth={1.6} />
      </svg>
    ),
  },
];

const EDGE_KINDS: { kind: string; hint: string; line: React.ReactNode }[] = [
  {
    kind: "scoped",
    hint: "target → scan",
    line: (
      <svg width="30" height="10" aria-hidden>
        <line x1={1} y1={5} x2={29} y2={5} stroke="#3f3f46" strokeWidth={1.1} />
      </svg>
    ),
  },
  {
    kind: "executed",
    hint: "scan → agent",
    line: (
      <svg width="30" height="10" aria-hidden>
        <line x1={1} y1={5} x2={29} y2={5} stroke="#52525b" strokeWidth={1.1} />
      </svg>
    ),
  },
  {
    kind: "produced",
    hint: "agent → finding",
    line: (
      <svg width="30" height="10" aria-hidden>
        <line x1={1} y1={5} x2={29} y2={5} stroke="#f97316" strokeWidth={1.5} strokeDasharray="7 4" />
      </svg>
    ),
  },
  {
    kind: "correlated",
    hint: "finding → chain",
    line: (
      <svg width="30" height="10" aria-hidden>
        <line x1={1} y1={5} x2={29} y2={5} stroke="#34d399" strokeWidth={1.4} strokeDasharray="2 5" />
      </svg>
    ),
  },
];

function StatChip({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="flex items-baseline gap-1.5 rounded-md border border-border bg-zinc-950/50 px-2.5 py-1.5">
      <span className="swarm-mono text-sm font-semibold tabular-nums text-primary">
        {value ?? "—"}
      </span>
      <span className="text-[10px] text-zinc-500">{label}</span>
    </div>
  );
}

export function GraphLegend({ stats }: { stats: GraphStats | null }) {
  return (
    <Card className="rounded-xl">
      <CardHeader className="px-4 pb-3 sm:px-5">
        <CardTitle className="text-sm">Legend &amp; stats</CardTitle>
        <CardDescription className="text-xs">
          The DAG reads left → right: targets → scans → agents → findings → attack chains
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 px-4 pb-4 sm:px-5">
        <div className="grid grid-cols-4 gap-1.5">
          <StatChip label="nodes" value={stats?.nodes ?? null} />
          <StatChip label="edges" value={stats?.edges ?? null} />
          <StatChip label="findings" value={stats?.findings ?? null} />
          <StatChip label="chains" value={stats?.chains ?? null} />
        </div>

        <div className="grid grid-cols-2 gap-x-4 gap-y-2">
          {NODE_KINDS.map((n) => (
            <div key={n.kind} className="flex items-center gap-2">
              {n.shape}
              <div className="min-w-0">
                <p className="text-[11px] leading-tight text-zinc-300">{n.kind}</p>
                <p className="text-[10px] leading-tight text-zinc-600">{n.hint}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="space-y-1.5 border-t border-border pt-3">
          {EDGE_KINDS.map((e) => (
            <div key={e.kind} className="flex items-center gap-2">
              {e.line}
              <span className="swarm-mono text-[10px] text-zinc-500">{e.hint}</span>
              <span className="ml-auto text-[10px] text-zinc-600">{e.kind}</span>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-border pt-3">
          {(Object.keys(SEVERITY_STYLES) as (keyof typeof SEVERITY_STYLES)[]).map((sev) => (
            <span key={sev} className="flex items-center gap-1.5">
              <span
                className={cn("h-2 w-2 rounded-full", SEVERITY_STYLES[sev].dot)}
                aria-hidden
              />
              <span className="text-[10px] text-zinc-400">{sev}</span>
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
