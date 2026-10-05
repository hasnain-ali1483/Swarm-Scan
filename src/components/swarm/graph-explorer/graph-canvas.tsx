"use client";

// ─── Force-directed finding-graph canvas (Task 9-a; live pulses: Task 12-a) ──
// Hand-rolled SVG force layout (no graph libs):
//  · deterministic seeded initial placement (mulberry32, fixed seed constant)
//  · physics loop on requestAnimationFrame — O(n²) repulsion, kind-specific
//    spring rest lengths along edges, kind gravity wells (DAG reads left→right),
//    velocity damping — freezes when kinetic energy drops below epsilon
//  · interaction: hover highlights the connected subgraph (dims the rest),
//    click/Enter selects a node for the inspector panel
//  · live pulses (Task 12-a): nodes listed in `pulseIds` (ids the live-graph
//    hook derived from finding:new bus events) render an expanding ring + a
//    brief white brighten overlay. Purely presentational — CSS keyframes on a
//    separate overlay group; the physics effect's deps never include pulseIds,
//    so pulsing NEVER restarts the layout or re-runs computeLayout.
// Node shapes: target = rounded square, scan = circle, agent = hexagon,
// finding = severity-colored circle, chain = diamond. Node size scales with
// degree. Edge strokes: produced = severity-colored dashed (animated flow when
// highlighted), correlated = emerald dotted, scoped/executed = zinc solid.

import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import type { GraphData, GraphNode, GraphNodeKind } from "@/lib/swarm/types";
import {
  KIND_BASE_RADIUS,
  agentStatusColor,
  hexPoints,
  scanStatusColor,
  severityColor,
  truncateLabel,
} from "./graph-style";

const VB_W = 1200;
const VB_H = 560;
const KIND_X: Record<GraphNodeKind, number> = {
  target: 92,
  scan: 368,
  agent: 640,
  finding: 912,
  chain: 1128,
};
const ZONE_LABEL: Record<GraphNodeKind, string> = {
  target: "TARGETS",
  scan: "SCANS",
  agent: "AGENTS",
  finding: "FINDINGS",
  chain: "CHAINS",
};
const SPREAD: Record<GraphNodeKind, number> = {
  target: 34,
  scan: 100,
  agent: 200,
  finding: 150,
  chain: 44,
};

// Edge kind → spring rest length (roughly the column gaps).
const REST_LEN: Record<string, number> = {
  scoped: 265,
  executed: 260,
  produced: 240,
  correlated: 195,
};

// Physics tuning.
const REPULSION = 1400;
const MAX_REPULSION = 6;
const REPULSION_CUTOFF = 150; // short-range repulsion — no cumulative column pressure
const SPRING_K = 0.012;
const WELL_K = 0.02; // pull toward the kind column (x)
const CENTER_K = 0.002; // weak vertical centering
const DAMPING = 0.82;
const MAX_SPEED = 9;
const ENERGY_EPS = 0.003; // mean squared velocity per node
const MAX_FRAMES = 480;
const TIME_CAP_MS = 4000;

// ── Deterministic PRNG (see mini-services/scan-engine/lib/rng.ts) ────────────

function mulberry32(a: number): () => number {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Pos {
  x: number;
  y: number;
}

function nodeRadius(kind: GraphNodeKind, degree: number): number {
  return KIND_BASE_RADIUS[kind] + Math.min(5, degree * 0.7);
}

/** Deterministic seeded initial placement — reproducible per graph data. */
function computeLayout(nodes: GraphNode[], degree: Map<string, number>): Map<string, Pos> {
  const rng = mulberry32(0x5eedba11);
  const byKind = new Map<GraphNodeKind, GraphNode[]>();
  for (const n of nodes) {
    const group = byKind.get(n.kind);
    if (group) group.push(n);
    else byKind.set(n.kind, [n]);
  }
  const pos = new Map<string, Pos>();
  const top = 36;
  const bottom = VB_H - 26;
  for (const [kind, group] of byKind) {
    group.forEach((n, i) => {
      const x = KIND_X[kind] + (rng() - 0.5) * SPREAD[kind];
      const y = top + ((i + 0.5) / group.length) * (bottom - top) + (rng() - 0.5) * 14;
      pos.set(n.id, { x, y });
    });
  }
  return pos;
}

// ── Node shape (pure) ────────────────────────────────────────────────────────

function NodeShape({ node, r }: { node: GraphNode; r: number }) {
  switch (node.kind) {
    case "target":
      return (
        <g>
          <rect
            x={-r}
            y={-r}
            width={r * 2}
            height={r * 2}
            rx={4}
            fill="#0c0c0e"
            stroke="#34d399"
            strokeWidth={1.4}
            className="gql-shape"
          />
          {/* server glyph */}
          <rect
            x={-r * 0.45}
            y={-r * 0.55}
            width={r * 0.9}
            height={r * 0.4}
            rx={1.5}
            fill="none"
            stroke="#34d399"
            strokeWidth={0.9}
          />
          <rect
            x={-r * 0.45}
            y={r * 0.14}
            width={r * 0.9}
            height={r * 0.4}
            rx={1.5}
            fill="none"
            stroke="#34d399"
            strokeWidth={0.9}
          />
          <circle cx={r * 0.26} cy={-r * 0.35} r={0.9} fill="#34d399" />
          <circle cx={r * 0.26} cy={r * 0.34} r={0.9} fill="#34d399" />
        </g>
      );
    case "scan":
      return (
        <circle
          r={r}
          fill="#101013"
          stroke={scanStatusColor(node.status)}
          strokeWidth={1.4}
          className="gql-shape"
        />
      );
    case "agent":
      return (
        <g>
          <polygon
            points={hexPoints(r)}
            fill="#0c0c0e"
            stroke={agentStatusColor(node.status)}
            strokeWidth={1.2}
            className="gql-shape"
          />
          <circle r={1.6} fill={agentStatusColor(node.status)} />
        </g>
      );
    case "finding": {
      const c = severityColor(node.severity);
      return (
        <g>
          <circle
            r={r}
            fill={c}
            fillOpacity={0.3}
            stroke={c}
            strokeWidth={1.6}
            className="gql-shape"
          />
          <circle r={1.4} fill={c} />
        </g>
      );
    }
    case "chain": {
      const stroke = node.status === "verified" ? "#34d399" : "#f59e0b";
      return (
        <g>
          <polygon
            points={`0,${-r} ${r},0 0,${r} ${-r},0`}
            fill="#0c0c0e"
            stroke={stroke}
            strokeWidth={1.6}
            className="gql-shape"
          />
          <circle r={1.6} fill={stroke} />
        </g>
      );
    }
  }
}

// ── Canvas component ─────────────────────────────────────────────────────────

export interface GraphCanvasProps {
  data: GraphData;
  selectedId: string | null;
  onSelect: (node: GraphNode) => void;
  /** Node ids currently pulsing (finding:new live events). Presentational only. */
  pulseIds?: Set<string>;
}

export function GraphCanvas({ data, selectedId, onSelect, pulseIds }: GraphCanvasProps) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [settled, setSettled] = useState(false);

  const nodeEls = useRef(new Map<string, SVGGElement>());
  const edgeEls = useRef(new Map<string, SVGLineElement>());

  const nodeById = useMemo(() => new Map(data.nodes.map((n) => [n.id, n])), [data]);

  const degree = useMemo(() => {
    const m = new Map<string, number>();
    for (const n of data.nodes) m.set(n.id, 0);
    for (const e of data.edges) {
      m.set(e.source, (m.get(e.source) ?? 0) + 1);
      m.set(e.target, (m.get(e.target) ?? 0) + 1);
    }
    return m;
  }, [data]);

  const adjacency = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const n of data.nodes) m.set(n.id, new Set<string>());
    for (const e of data.edges) {
      m.get(e.source)?.add(e.target);
      m.get(e.target)?.add(e.source);
    }
    return m;
  }, [data]);

  const layout = useMemo(() => computeLayout(data.nodes, degree), [data, degree]);

  // Force-directed simulation: mutates DOM attributes imperatively inside rAF.
  // React re-renders (hover/selection) never reset these attributes because
  // the rendered vdom values (from the deterministic initial layout) are
  // unchanged between renders.
  useEffect(() => {
    const sim = data.nodes.map((n) => {
      const p = layout.get(n.id) ?? { x: KIND_X[n.kind], y: VB_H / 2 };
      return { id: n.id, kind: n.kind, x: p.x, y: p.y, vx: 0, vy: 0 };
    });
    const byId = new Map(sim.map((s) => [s.id, s]));
    const pos = new Map(sim.map((s) => [s.id, { x: s.x, y: s.y }]));
    const edges = data.edges;

    let raf = 0;
    let frames = 0;
    let calm = 0;
    const t0 = performance.now();

    const tick = () => {
      // Repulsion between near node pairs — short-range (cutoff) so dense
      // columns don't exert cumulative long-range pressure on their neighbors.
      for (let i = 0; i < sim.length; i++) {
        const a = sim[i];
        for (let j = i + 1; j < sim.length; j++) {
          const b = sim[j];
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          let d2 = dx * dx + dy * dy;
          if (d2 > REPULSION_CUTOFF * REPULSION_CUTOFF) continue;
          if (d2 < 1) {
            // deterministic de-overlap nudge (no Math.random — reproducible)
            dx = 0.6;
            dy = 0.8;
            d2 = 1;
          }
          const d = Math.sqrt(d2);
          let f = REPULSION / d2;
          if (f > MAX_REPULSION) f = MAX_REPULSION;
          const fx = (dx / d) * f;
          const fy = (dy / d) * f;
          a.vx += fx;
          a.vy += fy;
          b.vx -= fx;
          b.vy -= fy;
        }
      }
      // Spring attraction along edges (kind-specific rest lengths).
      for (const e of edges) {
        const a = byId.get(e.source);
        const b = byId.get(e.target);
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.001;
        const f = SPRING_K * (d - (REST_LEN[e.kind] ?? 240));
        const fx = (dx / d) * f;
        const fy = (dy / d) * f;
        a.vx += fx;
        a.vy += fy;
        b.vx -= fx;
        b.vy -= fy;
      }
      // Kind gravity wells (horizontal) + weak vertical centering + integrate.
      for (const n of sim) {
        n.vx += WELL_K * (KIND_X[n.kind] - n.x);
        n.vy += CENTER_K * (VB_H / 2 - n.y);
        n.vx *= DAMPING;
        n.vy *= DAMPING;
        const sp = Math.hypot(n.vx, n.vy);
        if (sp > MAX_SPEED) {
          n.vx = (n.vx / sp) * MAX_SPEED;
          n.vy = (n.vy / sp) * MAX_SPEED;
        }
        n.x += n.vx;
        n.y += n.vy;
        n.x = Math.min(VB_W - 26, Math.max(26, n.x));
        n.y = Math.min(VB_H - 24, Math.max(30, n.y));
        pos.set(n.id, { x: n.x, y: n.y });
      }
      // Paint: update group transforms + edge endpoints.
      for (const n of sim) {
        nodeEls.current.get(n.id)?.setAttribute("transform", `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`);
      }
      for (const e of edges) {
        const el = edgeEls.current.get(e.id);
        const a = pos.get(e.source);
        const b = pos.get(e.target);
        if (el && a && b) {
          el.setAttribute("x1", a.x.toFixed(1));
          el.setAttribute("y1", a.y.toFixed(1));
          el.setAttribute("x2", b.x.toFixed(1));
          el.setAttribute("y2", b.y.toFixed(1));
        }
      }

      frames++;
      const energy = sim.reduce((s, n) => s + n.vx * n.vx + n.vy * n.vy, 0) / Math.max(1, sim.length);
      if (energy < ENERGY_EPS) calm++;
      else calm = 0;
      if ((calm >= 3 && frames > 30) || frames >= MAX_FRAMES || performance.now() - t0 > TIME_CAP_MS) {
        setSettled(true);
        return;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [data, layout, degree]);

  const focusId = hoveredId ?? selectedId;
  const focusSet = focusId ? adjacency.get(focusId) : undefined;

  // Focused + adjacent nodes render last (SVG paint order = DOM order).
  const orderedNodes = useMemo(() => {
    const rank = (n: GraphNode) => (n.id === focusId ? 2 : focusSet?.has(n.id) ? 1 : 0);
    return [...data.nodes].sort((a, b) => rank(a) - rank(b));
  }, [data, focusId, focusSet]);

  return (
    <div className="relative overflow-hidden rounded-lg border border-border bg-zinc-950/50 swarm-grid-bg">
      <style
        dangerouslySetInnerHTML={{
          __html: `
            @keyframes gql-dash-flow { to { stroke-dashoffset: -110; } }
            @keyframes gql-dot-flow { to { stroke-dashoffset: -105; } }
            .gql-edge-flow-dash { animation: gql-dash-flow 1.1s linear infinite; }
            .gql-edge-flow-dot { animation: gql-dot-flow 1.1s linear infinite; }
            .gql-node { cursor: pointer; }
            .gql-node:hover { filter: drop-shadow(0 0 5px rgba(52, 211, 153, 0.85)); }
            .gql-node:focus { outline: none; }
            .gql-node:focus-visible .gql-shape { stroke: #10b981; stroke-width: 2.4; }
            /* ── Live finding:new node pulses (Task 12-a) ──
               CSS keyframes (not SMIL: dynamically-inserted SMIL animates on the
               DOCUMENT timeline, so a late-mounted <animate begin="0s"> would
               already be mid-flight). The ring scales from the node radius to
               radius+14 three times over 1.5s each; the hook clears the pulse
               id after ~4.6s. transform-box keeps the scale centered on the
               node (circle geometry is centered at the group origin). */
            @keyframes gql-pulse-ring {
              from { transform: scale(var(--gql-pr)); opacity: 0.9; }
              to { transform: scale(var(--gql-pr2)); opacity: 0; }
            }
            @keyframes gql-pulse-brighten {
              from { opacity: 0.3; }
              to { opacity: 0; }
            }
            .gql-pulse-ring {
              transform-box: fill-box;
              transform-origin: center;
              transform: scale(var(--gql-pr));
              animation: gql-pulse-ring 1.5s cubic-bezier(0.2, 0.6, 0.35, 1) 3 both;
            }
            .gql-pulse-brighten {
              animation: gql-pulse-brighten 1.5s ease-out 1 both;
            }
            @media (max-width: 640px) {
              .gql-node-label, .gql-node-sub { display: none; }
            }
          `,
        }}
      />
      <svg
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        preserveAspectRatio="xMidYMid meet"
        className="block h-auto w-full min-h-[340px] lg:h-[520px]"
        role="img"
        aria-label={`Force-directed finding graph: ${data.stats.nodes} nodes and ${data.stats.edges} edges — targets, scans, agents, findings and attack chains flowing left to right. Tab to a node and press Enter to inspect it.`}
      >
        {/* zone labels */}
        {(Object.keys(KIND_X) as GraphNodeKind[]).map((kind) => (
          <text
            key={kind}
            x={KIND_X[kind]}
            y={16}
            textAnchor="middle"
            fontSize={9}
            letterSpacing={2}
            fill="#52525b"
            fontFamily="var(--font-mono)"
          >
            {ZONE_LABEL[kind]}
          </text>
        ))}

        {/* edges */}
        {data.edges.map((e) => {
          const a = layout.get(e.source);
          const b = layout.get(e.target);
          if (!a || !b) return null;
          const touched = focusId !== null && (e.source === focusId || e.target === focusId);
          const dim = focusId !== null && !touched;
          const targetNode = nodeById.get(e.target);
          let stroke = "#52525b";
          let strokeWidth = 1.1;
          let strokeDasharray: string | undefined;
          let opacity = 0.45;
          let flowClass: string | undefined;
          switch (e.kind) {
            case "scoped":
              stroke = "#3f3f46";
              opacity = 0.4;
              break;
            case "executed":
              stroke = "#52525b";
              opacity = 0.45;
              break;
            case "produced":
              stroke = severityColor(targetNode?.severity);
              strokeWidth = 1.5;
              strokeDasharray = "7 4";
              opacity = 0.75;
              flowClass = "gql-edge-flow-dash";
              break;
            case "correlated":
              stroke = "#34d399";
              strokeWidth = 1.4;
              strokeDasharray = "2 5";
              opacity = 0.85;
              flowClass = "gql-edge-flow-dot";
              break;
          }
          return (
            <line
              key={e.id}
              ref={(el) => {
                if (el) edgeEls.current.set(e.id, el);
                else edgeEls.current.delete(e.id);
              }}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={stroke}
              strokeWidth={touched ? strokeWidth + 0.6 : strokeWidth}
              strokeDasharray={touched && !strokeDasharray ? "6 4" : strokeDasharray}
              opacity={dim ? 0.06 : opacity}
              className={touched ? (flowClass ?? "gql-edge-flow-dash") : undefined}
              style={{ pointerEvents: "none" }}
            />
          );
        })}

        {/* nodes */}
        {orderedNodes.map((n) => {
          const p = layout.get(n.id) ?? { x: KIND_X[n.kind], y: VB_H / 2 };
          const r = nodeRadius(n.kind, degree.get(n.id) ?? 0);
          const dim = focusId !== null && n.id !== focusId && !focusSet?.has(n.id);
          const isSelected = n.id === selectedId;
          const isPulsing = pulseIds?.has(n.id) ?? false;
          const pulseRingColor =
            n.kind === "finding" ? severityColor(n.severity) : "#34d399";
          const showSub = n.kind === "target" || n.kind === "scan" || n.kind === "chain" || n.id === focusId;
          return (
            <g
              key={n.id}
              ref={(el) => {
                if (el) nodeEls.current.set(n.id, el);
                else nodeEls.current.delete(n.id);
              }}
              transform={`translate(${p.x} ${p.y})`}
              className="gql-node"
              role="button"
              tabIndex={0}
              aria-label={`${n.kind} node: ${n.label} — ${n.sub}`}
              opacity={dim ? 0.2 : 1}
              onMouseEnter={() => setHoveredId(n.id)}
              onMouseLeave={() =>
                setHoveredId((cur) => (cur === n.id ? null : cur))
              }
              onFocus={() => setHoveredId(n.id)}
              onBlur={() => setHoveredId((cur) => (cur === n.id ? null : cur))}
              onClick={() => onSelect(n)}
              onKeyDown={(ev) => {
                if (ev.key === "Enter" || ev.key === " ") {
                  ev.preventDefault();
                  onSelect(n);
                }
              }}
            >
              <title>{`${n.label} — ${n.sub}`}</title>
              {isSelected && (
                <circle
                  r={r + 5}
                  fill="none"
                  stroke="#10b981"
                  strokeWidth={1.2}
                  strokeDasharray="3 3"
                />
              )}
              {/* invisible hit-area halo (labels never intercept clicks) */}
              <circle r={r + 4} fill="transparent" style={{ pointerEvents: "all" }} />
              <NodeShape node={n} r={r} />
              {/* ── live pulse overlay (finding:new over the socket bus) ──
                  Presentational only: CSS-keyframed ring + brighten; never
                  touches the physics loop or the layout memo. */}
              {isPulsing && (
                <g className="gql-pulse" style={{ pointerEvents: "none" }} aria-hidden>
                  <circle r={r} fill="#ffffff" className="gql-pulse-brighten" />
                  <circle
                    r={1}
                    fill="none"
                    stroke={pulseRingColor}
                    strokeWidth={1.6}
                    vectorEffect="non-scaling-stroke"
                    className="gql-pulse-ring"
                    style={
                      {
                        "--gql-pr": String(r),
                        "--gql-pr2": String(r + 14),
                      } as CSSProperties
                    }
                  />
                </g>
              )}
              <text
                y={r + 10}
                textAnchor="middle"
                fontSize={10.5}
                fill={n.kind === "finding" ? "#8b8b93" : "#c2c2c8"}
                stroke="#09090b"
                strokeWidth={3}
                paintOrder="stroke"
                strokeLinejoin="round"
                fontFamily="var(--font-mono)"
                className="gql-node-label"
                style={{ pointerEvents: "none" }}
              >
                {truncateLabel(n.label, 16)}
              </text>
              {showSub && (
                <text
                  y={r + 21}
                  textAnchor="middle"
                  fontSize={8.5}
                  fill="#6f6f77"
                  stroke="#09090b"
                  strokeWidth={2.5}
                  paintOrder="stroke"
                  strokeLinejoin="round"
                  fontFamily="var(--font-mono)"
                  className="gql-node-sub"
                  style={{ pointerEvents: "none" }}
                >
                  {truncateLabel(n.sub, 26)}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* settling status + screen-reader caption */}
      <div className="pointer-events-none absolute bottom-2 right-3 flex items-center gap-1.5 font-mono text-[10px] text-zinc-400">
        {settled ? (
          <>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500/70" aria-hidden />
            layout settled · {data.stats.nodes} nodes / {data.stats.edges} edges
          </>
        ) : (
          <>
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500 swarm-pulse" aria-hidden />
            settling physics…
          </>
        )}
      </div>
      <span className="sr-only" aria-live="polite">
        {settled
          ? `Graph layout settled: ${data.stats.nodes} nodes, ${data.stats.edges} edges.`
          : "Graph layout animating."}
      </span>
    </div>
  );
}
