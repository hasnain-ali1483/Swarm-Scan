"use client";

// ─── Attack chain SVG graph ───────────────────────────────────────────────────
// Hand-rolled SVG (no external graph lib): layered/coordinate layout, typed
// node shapes (asset rect / finding circle / credential hexagon / impact burst),
// bezier edges with arrowheads, hover + selection focus, zoom & drag-pan.

import { useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Minus, Plus, RotateCcw, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import type { AttackChainItem, ChainGraphEdge, ChainGraphNode } from "@/lib/swarm/types";

const W = 1000;
const H = 420;

const SEVERITY_HEX: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#eab308",
  info: "#a1a1aa",
};

function nodeColor(node: ChainGraphNode): string {
  switch (node.type) {
    case "finding":
      return SEVERITY_HEX[node.severity ?? ""] ?? "#a1a1aa";
    case "credential":
      return "#f59e0b";
    case "impact":
      return "#ef4444";
    default:
      return "#a1a1aa";
  }
}

function nodeRadius(node: ChainGraphNode): number {
  switch (node.type) {
    case "asset":
      return 46;
    case "credential":
      return 32;
    case "impact":
      return 36;
    default:
      return 26;
  }
}

// ─── Layout ──────────────────────────────────────────────────────────────────

interface PositionedNode {
  node: ChainGraphNode;
  x: number;
  y: number;
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

function layoutChain(chain: AttackChainItem): PositionedNode[] {
  const nodes = chain.graph.nodes;
  const edges = chain.graph.edges;

  // Longest-path depth from roots (cycle-safe relaxation).
  const depth = new Map<string, number>();
  nodes.forEach((n) => depth.set(n.id, 0));
  for (let iter = 0; iter < Math.min(nodes.length, 24); iter += 1) {
    let changed = false;
    edges.forEach((e) => {
      const d = (depth.get(e.from) ?? 0) + 1;
      if (d > (depth.get(e.to) ?? 0) && d < 50) {
        depth.set(e.to, d);
        changed = true;
      }
    });
    if (!changed) break;
  }

  const maxDepth = nodes.reduce((m, n) => Math.max(m, depth.get(n.id) ?? 0), 0);

  // Explicit coordinates first (0..100 hints → viewBox units).
  const placed = new Map<string, { x: number; y: number }>();
  nodes.forEach((n) => {
    if (typeof n.x === "number" && typeof n.y === "number") {
      placed.set(n.id, { x: clamp(n.x * 10, 60, 940), y: clamp(n.y * 4.2, 44, 376) });
    }
  });

  // Layered fallback for nodes without coordinates.
  const layers = new Map<number, ChainGraphNode[]>();
  nodes.forEach((n) => {
    if (placed.has(n.id)) return;
    const d = depth.get(n.id) ?? 0;
    const arr = layers.get(d) ?? [];
    arr.push(n);
    layers.set(d, arr);
  });

  layers.forEach((members, d) => {
    const layerX = maxDepth === 0 ? 500 : 120 + (d / maxDepth) * 760;
    members.forEach((n, i) => {
      const spread = 300 / (members.length + 1);
      placed.set(n.id, {
        x: clamp(layerX + (i % 2 === 0 ? -36 : 36), 60, 940),
        y: clamp(60 + (i + 1) * spread, 44, 376),
      });
    });
  });

  return nodes.map((n) => {
    const pos = placed.get(n.id) ?? { x: 500, y: 210 };
    return { node: n, x: pos.x, y: pos.y };
  });
}

// ─── Geometry helpers ────────────────────────────────────────────────────────

function hexagonPoints(r: number): string {
  const pts: string[] = [];
  for (let k = 0; k < 6; k += 1) {
    const a = (Math.PI / 180) * (60 * k);
    pts.push(`${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`);
  }
  return pts.join(" ");
}

function burstPoints(spikes: number, outer: number, inner: number): string {
  const pts: string[] = [];
  for (let k = 0; k < spikes; k += 1) {
    const ao = (Math.PI / 180) * ((360 / spikes) * k);
    const ai = (Math.PI / 180) * ((360 / spikes) * k + 180 / spikes);
    pts.push(`${(outer * Math.cos(ao)).toFixed(1)},${(outer * Math.sin(ao)).toFixed(1)}`);
    pts.push(`${(inner * Math.cos(ai)).toFixed(1)},${(inner * Math.sin(ai)).toFixed(1)}`);
  }
  return pts.join(" ");
}

function edgeGeometry(a: PositionedNode, b: PositionedNode) {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const dist = Math.hypot(dx, dy) || 1;
  const ra = nodeRadius(a.node) + 8;
  const rb = nodeRadius(b.node) + 12;
  const sx = a.x + (dx / dist) * ra;
  const sy = a.y + (dy / dist) * ra;
  const ex = b.x - (dx / dist) * rb;
  const ey = b.y - (dy / dist) * rb;
  const curve = Math.min(30, dist * 0.22);
  const cx = (sx + ex) / 2 + (-dy / dist) * curve;
  const cy = (sy + ey) / 2 + (dx / dist) * curve;
  return {
    d: `M ${sx.toFixed(1)} ${sy.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${ex.toFixed(1)} ${ey.toFixed(1)}`,
    label: { x: (sx + 2 * cx + ex) / 4, y: (sy + 2 * cy + ey) / 4 },
  };
}

/** Wrap a node label to at most two ~18-char lines. */
function wrapLabel(label: string, max = 18): string[] {
  if (label.length <= max) return [label];
  const words = label.split(/\s+/);
  const lines: string[] = [];
  let cur = "";
  for (const w of words) {
    if ((cur ? `${cur} ${w}` : w).length <= max) {
      cur = cur ? `${cur} ${w}` : w;
    } else {
      if (cur) lines.push(cur);
      cur = w.length > max ? `${w.slice(0, max - 1)}…` : w;
    }
  }
  if (cur) lines.push(cur);
  if (lines.length > 2) {
    lines.length = 2;
    lines[1] = `${lines[1].slice(0, max - 1)}…`;
  }
  return lines;
}

// ─── Node shape ──────────────────────────────────────────────────────────────

function NodeShape({ pn, selected }: { pn: PositionedNode; selected: boolean }) {
  const { node } = pn;
  const color = nodeColor(node);
  const r = nodeRadius(node);
  const lines = wrapLabel(node.label);
  const below = node.type !== "asset";
  const labelY = node.type === "impact" ? [50, 63] : node.type === "credential" ? [46, 59] : [42, 55];

  return (
    <>
      {selected ? (
        <>
          <circle r={r + 16} fill="#34d399" fillOpacity={0.06} />
          <circle r={r + 16} fill="none" stroke="#34d399" strokeWidth={1.5} strokeDasharray="5 4" />
        </>
      ) : null}

      {node.type === "asset" ? (
        <rect x={-72} y={-25} width={144} height={50} rx={10} fill="#18181b" fillOpacity={0.92} stroke="#71717a" strokeWidth={1.5} />
      ) : node.type === "credential" ? (
        <polygon points={hexagonPoints(30)} fill={color} fillOpacity={0.1} stroke={color} strokeWidth={1.8} />
      ) : node.type === "impact" ? (
        <polygon points={burstPoints(8, 34, 15)} fill={color} fillOpacity={0.16} stroke={color} strokeWidth={1.8} filter="url(#sg-impact-glow)" />
      ) : (
        <circle r={26} fill={color} fillOpacity={0.12} stroke={color} strokeWidth={2} />
      )}

      {/* labels */}
      {below ? (
        lines.map((line, i) => (
          <text key={i} y={labelY[i]} textAnchor="middle" fontSize="11" fill="#d4d4d8" pointerEvents="none">
            {line}
          </text>
        ))
      ) : (
        lines.map((line, i) => (
          <text
            key={i}
            y={lines.length === 1 ? 4 : i === 0 ? -3 : 13}
            textAnchor="middle"
            fontSize="11"
            fill="#d4d4d8"
            pointerEvents="none"
          >
            {line}
          </text>
        ))
      )}
    </>
  );
}

// ─── Graph ───────────────────────────────────────────────────────────────────

export function ChainGraph({ chain }: { chain: AttackChainItem }) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const dragRef = useRef<{ px: number; py: number; startPan: { x: number; y: number }; moved: number } | null>(null);
  const lastMovedRef = useRef(0);

  // NOTE: the parent renders <ChainGraph key={chain.id} … /> so a chain switch
  // remounts this component and resets zoom/pan/selection automatically.

  const positioned = useMemo(() => layoutChain(chain), [chain]);
  const posMap = useMemo(() => new Map(positioned.map((p) => [p.node.id, p])), [positioned]);

  const vbW = W / zoom;
  const vbH = H / zoom;
  const vbX = (W - vbW) / 2 + pan.x;
  const vbY = (H - vbH) / 2 + pan.y;

  const focusId = hoverId ?? selectedId;
  const selectedNode = selectedId ? posMap.get(selectedId)?.node ?? null : null;

  const onPointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    dragRef.current = { px: e.clientX, py: e.clientY, startPan: pan, moved: 0 };
    try {
      svgRef.current?.setPointerCapture(e.pointerId);
    } catch {
      // pointer capture is best-effort
    }
  };

  const onPointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const d = dragRef.current;
    if (!d || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    if (rect.width === 0) return;
    const scale = (W / zoom) / rect.width;
    const dx = e.clientX - d.px;
    const dy = e.clientY - d.py;
    d.moved = Math.max(d.moved, Math.abs(dx) + Math.abs(dy));
    setPan({ x: d.startPan.x - dx * scale, y: d.startPan.y - dy * scale });
  };

  const onPointerUp = () => {
    if (dragRef.current) lastMovedRef.current = dragRef.current.moved;
    dragRef.current = null;
  };

  const selectNode = (id: string) => {
    if (lastMovedRef.current > 6) return; // was a drag, not a click
    setSelectedId((prev) => (prev === id ? null : id));
  };

  return (
    <Card className="gap-4">
      <CardHeader className="pb-0">
        <CardTitle className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
          Exploitation path
          <span className="text-zinc-500">·</span>
          <span className="min-w-0 truncate font-normal text-zinc-300">{chain.name}</span>
          <Badge
            variant="outline"
            className={cn("px-1.5 py-0 text-[10px] uppercase", SEVERITY_STYLES[chain.severity]?.badge ?? "")}
          >
            {SEVERITY_STYLES[chain.severity]?.label ?? chain.severity}
          </Badge>
        </CardTitle>
        <CardDescription className="text-xs">
          Correlated findings composed by CorrelatorAgent — drag to pan, click nodes for detail.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <div className="relative overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950/70">
          {/* zoom controls */}
          <div className="absolute right-2 top-2 z-10 flex items-center gap-1 rounded-md border border-zinc-800 bg-zinc-950/90 p-0.5">
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setZoom((z) => Math.min(2.5, z * 1.25))} aria-label="Zoom in" disabled={zoom >= 2.5}>
              <Plus className="h-3.5 w-3.5" aria-hidden />
            </Button>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setZoom((z) => Math.max(0.6, z / 1.25))} aria-label="Zoom out" disabled={zoom <= 0.6}>
              <Minus className="h-3.5 w-3.5" aria-hidden />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
              }}
              aria-label="Reset viewport"
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden />
            </Button>
          </div>

          {/* node detail popover */}
          {selectedNode ? (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className="absolute bottom-2.5 left-2.5 z-10 max-w-[260px] rounded-lg border border-zinc-700/70 bg-zinc-950/95 p-3 shadow-lg backdrop-blur"
              role="status"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{selectedNode.label}</p>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    <Badge variant="outline" className="border-zinc-700/70 bg-zinc-900/60 px-1.5 py-0 text-[10px] uppercase tracking-wide text-zinc-400">
                      {selectedNode.type}
                    </Badge>
                    {selectedNode.type === "finding" && selectedNode.severity ? (
                      <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", SEVERITY_STYLES[selectedNode.severity as keyof typeof SEVERITY_STYLES]?.badge ?? "")}>
                        {SEVERITY_STYLES[selectedNode.severity as keyof typeof SEVERITY_STYLES]?.label ?? selectedNode.severity}
                      </Badge>
                    ) : null}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedId(null)}
                  aria-label="Close node details"
                  className="shrink-0 rounded p-0.5 text-zinc-500 hover:bg-zinc-800 hover:text-zinc-200"
                >
                  <X className="h-3.5 w-3.5" aria-hidden />
                </button>
              </div>
              {selectedNode.detail ? (
                <p className="mt-2 break-words text-[11px] leading-relaxed text-zinc-400">{selectedNode.detail}</p>
              ) : null}
            </motion.div>
          ) : null}

          <svg
            ref={svgRef}
            viewBox={`${vbX.toFixed(2)} ${vbY.toFixed(2)} ${vbW.toFixed(2)} ${vbH.toFixed(2)}`}
            className="h-auto min-h-[280px] w-full cursor-grab touch-none select-none active:cursor-grabbing"
            role="img"
            aria-label={`Attack chain graph: ${chain.name}, ${positioned.length} nodes`}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerLeave={onPointerUp}
            onPointerCancel={onPointerUp}
          >
            <defs>
              <marker id="sg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#52525b" />
              </marker>
              <marker id="sg-arrow-hi" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#34d399" />
              </marker>
              <filter id="sg-impact-glow" x="-60%" y="-60%" width="220%" height="220%">
                <feDropShadow dx="0" dy="0" stdDeviation="6" floodColor="#ef4444" floodOpacity="0.55" />
              </filter>
            </defs>

            {/* edges */}
            {chain.graph.edges.map((edge: ChainGraphEdge, i: number) => {
              const a = posMap.get(edge.from);
              const b = posMap.get(edge.to);
              if (!a || !b) return null;
              const active = focusId != null && (edge.from === focusId || edge.to === focusId);
              const dim = focusId != null && !active;
              const geo = edgeGeometry(a, b);
              return (
                <g key={`${edge.from}->${edge.to}-${i}`} opacity={dim ? 0.22 : 1}>
                  <motion.path
                    d={geo.d}
                    fill="none"
                    stroke={active ? "#34d399" : "#52525b"}
                    strokeWidth={active ? 2 : 1.5}
                    markerEnd={`url(#${active ? "sg-arrow-hi" : "sg-arrow"})`}
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: 0.7, delay: 0.08 * i, ease: "easeOut" }}
                  />
                  {edge.label ? (
                    <text
                      x={geo.label.x}
                      y={geo.label.y - 4}
                      textAnchor="middle"
                      fontSize="9"
                      fill={active ? "#34d399" : "#71717a"}
                      pointerEvents="none"
                    >
                      {edge.label}
                    </text>
                  ) : null}
                </g>
              );
            })}

            {/* nodes */}
            {positioned.map((pn, i) => {
              const selected = pn.node.id === selectedId;
              return (
                <motion.g
                  key={pn.node.id}
                  transform={`translate(${pn.x} ${pn.y})`}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.35, delay: 0.15 + i * 0.06 }}
                  style={{ cursor: "pointer" }}
                  tabIndex={0}
                  role="button"
                  aria-label={`${pn.node.type} node: ${pn.node.label}${pn.node.severity ? `, severity ${pn.node.severity}` : ""}`}
                  onClick={() => selectNode(pn.node.id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setSelectedId((prev) => (prev === pn.node.id ? null : pn.node.id));
                    }
                  }}
                  onMouseEnter={() => setHoverId(pn.node.id)}
                  onMouseLeave={() => setHoverId(null)}
                  onFocus={() => setHoverId(pn.node.id)}
                  onBlur={() => setHoverId(null)}
                >
                  <NodeShape pn={pn} selected={selected} />
                </motion.g>
              );
            })}
          </svg>
        </div>

        {/* legend */}
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[10px] text-zinc-500">
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm border border-zinc-500 bg-zinc-900" aria-hidden />
            asset
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full border border-amber-500 bg-amber-500/20" aria-hidden />
            finding
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm border border-amber-500 bg-amber-500/10 [clip-path:polygon(50%_0,100%_25%,100%_75%,50%_100%,0_75%,0_25%)]" aria-hidden />
            credential
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500/40 shadow-[0_0_6px_rgba(239,68,68,0.7)]" aria-hidden />
            impact
          </span>
          <span className="ml-auto font-mono text-zinc-600">sha256-anchored evidence · zoom {zoom.toFixed(2)}×</span>
        </div>
      </CardContent>
    </Card>
  );
}
