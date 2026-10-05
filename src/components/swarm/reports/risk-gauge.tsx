"use client";

// ─── Radial risk gauge — 0–100 aggregate risk score ───────────────────────────

import { cn } from "@/lib/swarm/format";

function riskTone(score: number) {
  if (score >= 70) {
    return {
      stroke: "stroke-red-500",
      text: "text-red-400",
      label: "critical",
    } as const;
  }
  if (score >= 40) {
    return {
      stroke: "stroke-amber-500",
      text: "text-amber-400",
      label: "elevated",
    } as const;
  }
  return {
    stroke: "stroke-emerald-500",
    text: "text-emerald-400",
    label: "low",
  } as const;
}

export function RiskGauge({ score, size = 176 }: { score: number; size?: number }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const tone = riskTone(clamped);
  const R = 80;
  const CIRC = 2 * Math.PI * R;
  const dash = (clamped / 100) * CIRC;

  return (
    <div
      className="relative"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Aggregate risk score ${clamped} of 100 — ${tone.label} risk`}
    >
      <svg viewBox="0 0 200 200" className="h-full w-full -rotate-90" aria-hidden>
        {/* subtle tick ring */}
        <circle
          cx="100"
          cy="100"
          r={R + 13}
          fill="none"
          strokeWidth="1"
          className="stroke-zinc-800"
          strokeDasharray="1 6"
        />
        <circle
          cx="100"
          cy="100"
          r={R}
          fill="none"
          strokeWidth="12"
          className="stroke-zinc-800/70"
        />
        <circle
          cx="100"
          cy="100"
          r={R}
          fill="none"
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${CIRC - dash}`}
          className={cn(tone.stroke, "transition-all duration-700")}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn("font-mono text-4xl font-semibold leading-none", tone.text)}>
          {clamped}
        </span>
        <span className="mt-1 font-mono text-[10px] text-zinc-500">/ 100</span>
        <span
          className={cn(
            "mt-1.5 rounded-sm border px-1.5 py-px text-[10px] uppercase tracking-wider",
            tone.text,
            "border-current/30 bg-current/10"
          )}
        >
          {tone.label}
        </span>
      </div>
    </div>
  );
}
