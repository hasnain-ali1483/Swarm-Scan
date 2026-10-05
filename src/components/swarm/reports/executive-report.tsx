"use client";

// ─── Executive report — risk score hero, summary, breakdown, top chains ──────

import { BadgeCheck, ShieldX } from "lucide-react";
import type { CSSProperties } from "react";
import { cn, SEVERITY_STYLES, timeAgo } from "@/lib/swarm/format";
import type { ReportResponse, Severity } from "@/lib/swarm/types";
import { RiskGauge } from "./risk-gauge";

function severityDot(sev: string) {
  return SEVERITY_STYLES[sev as Severity]?.dot ?? "bg-zinc-500";
}

/** The API color is either a hex string or a Tailwind class — support both. */
function toneClass(color?: string): string | undefined {
  return color && !color.startsWith("#") ? color : undefined;
}
function toneStyle(color?: string): CSSProperties | undefined {
  return color?.startsWith("#") ? { backgroundColor: color } : undefined;
}

/** Stacked horizontal bar + legend from the API's riskBreakdown. */
function RiskBreakdownBar({
  breakdown,
}: {
  breakdown: { label: string; count: number; color: string }[];
}) {
  const total = breakdown.reduce((sum, b) => sum + b.count, 0);
  if (total === 0) {
    return <p className="text-xs text-zinc-500">No findings recorded.</p>;
  }
  return (
    <div>
      <div
        className="flex h-3 w-full overflow-hidden rounded-full border border-zinc-800 bg-zinc-900"
        role="img"
        aria-label={breakdown.map((b) => `${b.label}: ${b.count}`).join(", ")}
      >
        {breakdown.map((b) =>
          b.count > 0 ? (
            <div
              key={b.label}
              className={cn("h-full min-w-[2px] transition-all", toneClass(b.color))}
              style={toneStyle(b.color)}
            />
          ) : null
        )}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3 lg:grid-cols-5">
        {breakdown.map((b) => (
          <div key={b.label} className="flex items-center gap-2">
            <span
              className={cn(
                "h-2.5 w-2.5 shrink-0 rounded-sm border border-zinc-800",
                toneClass(b.color)
              )}
              style={toneStyle(b.color)}
              aria-hidden
            />
            <span className="text-xs text-zinc-400">{b.label}</span>
            <span className="ml-auto font-mono text-xs text-zinc-200">{b.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ExecutiveReport({ report }: { report: ReportResponse }) {
  const riskScore = report.riskScore ?? 0;
  const breakdown = report.riskBreakdown ?? [];
  const chains = report.topChains ?? [];

  return (
    <div className="space-y-4">
      {/* hero: gauge + summary */}
      <div className="grid gap-4 lg:grid-cols-[auto_1fr]">
        <section
          aria-label="Aggregate risk score"
          className="flex flex-col items-center justify-center rounded-lg border border-zinc-800 bg-card/60 p-6"
        >
          <RiskGauge score={riskScore} />
          <p className="mt-4 text-[11px] uppercase tracking-widest text-zinc-400">
            Aggregate risk score
          </p>
          <p className="mt-1 font-mono text-[10px] text-zinc-600">
            {report.target}
          </p>
        </section>

        <section
          aria-labelledby="exec-summary-heading"
          className="rounded-lg border border-zinc-800 bg-card/60 p-6"
        >
          <h3 id="exec-summary-heading" className="text-sm font-semibold tracking-tight">
            Executive summary
          </h3>
          <p className="mt-3 text-sm leading-relaxed text-zinc-300">
            {report.executiveSummary ?? "No executive summary generated for this scan."}
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {breakdown.map((b) => (
              <span
                key={b.label}
                className="rounded-sm border border-zinc-800 bg-zinc-900/50 px-2 py-0.5 font-mono text-[10px] text-zinc-400"
              >
                {b.label} <span className="text-zinc-200">{b.count}</span>
              </span>
            ))}
          </div>
        </section>
      </div>

      {/* risk breakdown */}
      <section
        aria-labelledby="risk-breakdown-heading"
        className="rounded-lg border border-zinc-800 bg-card/60 p-6"
      >
        <h3 id="risk-breakdown-heading" className="text-sm font-semibold tracking-tight">
          Risk breakdown
        </h3>
        <div className="mt-4">
          <RiskBreakdownBar breakdown={breakdown} />
        </div>
      </section>

      {/* top chains */}
      <section
        aria-labelledby="top-chains-heading"
        className="rounded-lg border border-zinc-800 bg-card/60 p-6"
      >
        <h3 id="top-chains-heading" className="text-sm font-semibold tracking-tight">
          Top attack chains
        </h3>
        {chains.length === 0 ? (
          <p className="mt-3 text-xs text-zinc-500">
            No correlated attack chains were reachable for this target.
          </p>
        ) : (
          <ul className="mt-3 divide-y divide-zinc-800/70">
            {chains.map((chain) => (
              <li key={chain.name} className="flex items-center gap-3 py-2.5">
                <span
                  className={cn("h-2.5 w-2.5 shrink-0 rounded-full", severityDot(chain.severity))}
                  aria-label={`${chain.severity} severity`}
                />
                <span className="min-w-0 flex-1 truncate text-sm text-zinc-200">{chain.name}</span>
                {chain.verified ? (
                  <span className="flex shrink-0 items-center gap-1 rounded-sm border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-px text-[10px] text-emerald-400">
                    <BadgeCheck className="h-3 w-3" aria-hidden />
                    verified
                  </span>
                ) : (
                  <span className="flex shrink-0 items-center gap-1 rounded-sm border border-zinc-700 bg-zinc-900/50 px-1.5 py-px text-[10px] text-zinc-500">
                    <ShieldX className="h-3 w-3" aria-hidden />
                    unverified
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
        <p className="mt-4 text-[11px] text-zinc-500">
          Chains enumerate preconditions → enablements → impact as a planning problem; verified
          chains carry a machine-executable PoC plan.
        </p>
      </section>

      <p className="text-right font-mono text-[11px] text-zinc-500">
        generated {timeAgo(report.generatedAt)}
      </p>
    </div>
  );
}
