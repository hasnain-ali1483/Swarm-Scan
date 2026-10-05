"use client";

// ─── Bayesian confidence panel ────────────────────────────────────────────────
// Left: animated radial gauge (0–99). Right: the Bayesian odds computation,
// rendered like a worksheet so the math is fully visible:
//   O₀ prior → eᵢ likelihood ratios → O₁ = O₀·∏LR → P = O₁/(1+O₁)

import { useEffect, useMemo } from "react";
import { animate, motion, useMotionValue, useTransform } from "framer-motion";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BAND_STYLES, cn } from "@/lib/swarm/format";
import { type Finding } from "@/lib/swarm/types";
import { evidenceKindMeta } from "./evidence-kinds";

const BAND_HEX: Record<string, string> = {
  suspected: "#a1a1aa",
  likely: "#fbbf24",
  confirmed: "#34d399",
};

const SUBSCRIPTS = ["₀", "₁", "₂", "₃", "₄", "₅", "₆", "₇", "₈", "₉"];

function sub(n: number): string {
  return String(n)
    .split("")
    .map((d) => SUBSCRIPTS[Number(d)] ?? d)
    .join("");
}

/** Compact fixed-point formatting for the math worksheet. */
function fmt(n: number): string {
  if (n >= 1000) return n.toLocaleString("en-US", { maximumFractionDigits: 1 });
  if (n >= 100) return n.toFixed(1);
  if (n >= 1) return n.toFixed(2);
  if (n >= 0.001) return n.toFixed(3);
  return n.toExponential(2);
}

/** Point on the gauge arc for a confidence value at a given radius. */
function polar(value: number, radius: number): { x: number; y: number } {
  const angle = Math.PI * (1 - Math.min(99, Math.max(0, value)) / 99);
  return { x: 110 + radius * Math.cos(angle), y: 116 - radius * Math.sin(angle) };
}

function Gauge({ confidence, band }: { confidence: number; band: string }) {
  const color = BAND_HEX[band] ?? BAND_HEX.suspected;
  const arc = "M 22 116 A 94 94 0 0 1 198 116";
  const fraction = Math.min(1, Math.max(0, confidence / 99));

  const value = useMotionValue(0);
  const rounded = useTransform(value, (v) => v.toFixed(1));

  useEffect(() => {
    const controls = animate(value, confidence, { duration: 1.1, ease: "easeOut" });
    return () => controls.stop();
  }, [value, confidence]);

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-full max-w-[240px]">
        <svg viewBox="0 0 220 132" className="h-auto w-full" role="img" aria-label={`Confidence ${confidence.toFixed(1)} out of 99, band ${band}`}>
          <path d={arc} fill="none" stroke="#27272a" strokeWidth="10" strokeLinecap="round" />
          <motion.path
            d={arc}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            initial={{ pathLength: 0 }}
            animate={{ pathLength: fraction }}
            transition={{ duration: 1.1, ease: "easeOut" }}
          />
          {/* band threshold ticks */}
          {[60, 85].map((v) => {
            const a = polar(v, 84);
            const b = polar(v, 102);
            const l = polar(v, 72);
            return (
              <g key={v}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#52525b" strokeWidth="1.5" />
                <text x={l.x} y={l.y + 3} fontSize="9" fill="#71717a" textAnchor="middle" fontFamily="var(--font-geist-mono)">
                  {v}
                </text>
              </g>
            );
          })}
        </svg>
        <div className="pointer-events-none absolute inset-x-0 top-[46%] flex items-baseline justify-center gap-1" aria-hidden>
          <motion.span className="font-mono text-4xl font-bold tabular-nums text-foreground">{rounded}</motion.span>
          <span className="font-mono text-sm text-zinc-500">/99</span>
        </div>
      </div>
      <Badge variant="outline" className={cn("mt-1 gap-1.5 text-[11px]", BAND_STYLES[band as keyof typeof BAND_STYLES]?.badge ?? BAND_STYLES.suspected.badge)}>
        {BAND_STYLES[band as keyof typeof BAND_STYLES]?.label ?? band}
      </Badge>
    </div>
  );
}

/** One aligned worksheet line. */
function Line({
  label,
  term,
  children,
  className,
}: {
  label?: string;
  term?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-baseline gap-3", className)}>
      {label !== undefined ? (
        <span className="w-24 shrink-0 text-right text-zinc-500">{label}</span>
      ) : (
        <span className="w-24 shrink-0" aria-hidden />
      )}
      {term !== undefined ? <span className="w-9 shrink-0 text-zinc-400">{term}</span> : <span className="w-9 shrink-0" aria-hidden />}
      <span className="min-w-0 flex-1 break-words text-zinc-200">{children}</span>
    </div>
  );
}

export function ConfidencePanel({ finding }: { finding: Finding }) {
  const evidence = useMemo(
    () => [...(finding.evidence ?? [])].sort((a, b) => a.sequence - b.sequence),
    [finding.evidence]
  );
  const lrEvidence = evidence.filter((e) => e.lr > 0);

  const prior = finding.priorOdds;
  const product = finding.likelihood; // ∏LR as recorded
  const o1 = prior * product;
  const p = o1 / (1 + o1);
  const band = finding.band;

  const distinctKinds = new Set(evidence.map((e) => e.kind)).size;
  const twoTechnique = distinctKinds >= 2;

  return (
    <Card className="gap-4 overflow-hidden">
      <CardHeader className="pb-0">
        <CardTitle className="text-sm">Bayesian Confidence</CardTitle>
        <CardDescription className="text-xs">
          Posterior odds from the prior and each technique&apos;s likelihood ratio — the same
          computation the engine used to score this finding.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid items-center gap-6 lg:grid-cols-[minmax(220px,280px)_minmax(0,1fr)]">
          {/* gauge */}
          <Gauge confidence={finding.confidence} band={band} />

          {/* math worksheet */}
          <div className="min-w-0 space-y-2 rounded-lg border border-zinc-800 bg-zinc-950/70 p-4 font-mono text-xs leading-6">
            <Line label="prior odds" term="O₀">
              = {fmt(prior)}
            </Line>

            <div className="!mt-3 space-y-1">
              {lrEvidence.length > 0 ? (
                lrEvidence.map((e, i) => (
                  <Line key={e.id} label={i === 0 ? "evidence" : undefined} term={`e${sub(i + 1)}`}>
                    <span className="inline-flex flex-wrap items-baseline gap-x-2">
                      <span className={cn("rounded border px-1.5 py-px text-[10px]", evidenceKindMeta(e.kind).badge)}>
                        {evidenceKindMeta(e.kind).label}
                      </span>
                      <span className="text-zinc-400">LR</span>
                      <span className="text-zinc-100">{e.lr.toFixed(1)}</span>
                    </span>
                  </Line>
                ))
              ) : (
                <Line label="evidence" term="—">
                  <span className="text-zinc-500">no likelihood-ratio evidence recorded</span>
                </Line>
              )}
            </div>

            <Line label="" term="" className="!mt-1">
              <span className="text-zinc-500">∏LR = {fmt(product)}</span>
            </Line>

            <Line label="posterior odds" term="O₁" className="!mt-3 border-t border-zinc-800/70 pt-2">
              <span className="text-zinc-300">
                = O₀ · ∏LR = {fmt(prior)} × {fmt(product)} ={" "}
                <span className="font-semibold text-emerald-400">{fmt(o1)}</span>
              </span>
            </Line>

            <Line label="confidence" term="P" className="!mt-1">
              <span className="text-zinc-300">
                = O₁/(1+O₁) = {o1.toFixed(1)} / {(o1 + 1).toFixed(1)} = {p.toFixed(5)} →{" "}
                <span className="font-semibold text-emerald-400">{finding.confidence.toFixed(1)} / 99</span>{" "}
                <Badge
                  variant="outline"
                  className={cn("ml-1 px-1.5 py-0 align-middle text-[10px]", BAND_STYLES[band].badge)}
                >
                  {BAND_STYLES[band].label}
                </Badge>
              </span>
            </Line>
          </div>
        </div>

        {/* band thresholds + two-technique rule */}
        <div className="mt-4 flex flex-col gap-2.5 border-t border-zinc-800/70 pt-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[10px] text-zinc-500">
            <span className="text-zinc-600">bands:</span>
            <span className="flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" aria-hidden />0–59 suspected
            </span>
            <span className="flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-500" aria-hidden />60–84 likely
            </span>
            <span className="flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden />85–99 confirmed
            </span>
          </p>
          {twoTechnique ? (
            <p className="flex items-center gap-1.5 text-xs text-emerald-400">
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden />
              Two-technique confirmation satisfied
            </p>
          ) : (
            <p className="flex items-center gap-1.5 text-xs text-amber-400">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden />
              single-technique — informational only
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
