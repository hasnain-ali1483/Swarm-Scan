"use client";

// ─── CI gate status visuals (shared by the Benchmark section + Integrations strip) ──

import { Check, Loader2, Lock, LockOpen, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/swarm/format";
import type { CiGateRow, CiGatesSummary } from "@/lib/swarm/types";

/** Per-agent gate verdict badge: passed → emerald check, failed → red X, running → amber pulse. */
export function GateStatusBadge({ status }: { status: CiGateRow["status"] }) {
  if (status === "passed") {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-emerald-500/40 bg-emerald-500/10 font-mono text-[10px] text-emerald-400"
      >
        <Check className="h-3 w-3" aria-hidden />
        PASS
      </Badge>
    );
  }
  if (status === "failed") {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-destructive/40 bg-destructive/10 font-mono text-[10px] text-destructive"
      >
        <XCircle className="h-3 w-3" aria-hidden />
        FAIL
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="gap-1 border-amber-500/40 bg-amber-500/10 font-mono text-[10px] text-amber-400"
    >
      <Loader2 className="h-3 w-3 animate-pulse" aria-hidden />
      RUNNING
    </Badge>
  );
}

export type RegistryPublishState = "unlocked" | "blocked" | "pending";

/**
 * Registry publish verdict from the gate summary: unlocked only when every
 * gate passed; blocked when any gate failed; pending while gates are still
 * running without failures (e.g. awaiting first benchmark run).
 */
export function registryPublishState(summary: CiGatesSummary): RegistryPublishState {
  if (summary.total > 0 && summary.passed === summary.total) return "unlocked";
  if (summary.failed > 0) return "blocked";
  return "pending";
}

/** Agent-registry publish badge for the gates summary strip. */
export function RegistryPublishBadge({ state }: { state: RegistryPublishState }) {
  if (state === "unlocked") {
    return (
      <Badge
        variant="outline"
        className="gap-1.5 border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 font-mono text-[10px] text-emerald-400"
      >
        <LockOpen className="h-3.5 w-3.5" aria-hidden />
        agent registry: publish unlocked
      </Badge>
    );
  }
  if (state === "blocked") {
    return (
      <Badge
        variant="outline"
        className="gap-1.5 border-destructive/50 bg-destructive/10 px-2.5 py-1 font-mono text-[10px] text-destructive"
      >
        <Lock className="h-3.5 w-3.5" aria-hidden />
        agent registry: publish blocked
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="gap-1.5 border-amber-500/40 bg-amber-500/10 px-2.5 py-1 font-mono text-[10px] text-amber-400"
    >
      <Loader2 className="h-3.5 w-3.5 animate-pulse" aria-hidden />
      agent registry: publish pending
    </Badge>
  );
}

/** Segmented passed/failed/running progress bar (emerald / red / amber). */
export function GatesProgressBar({
  summary,
  className,
}: {
  summary: CiGatesSummary | undefined;
  className?: string;
}) {
  const total = summary?.total ?? 0;
  const passed = summary?.passed ?? 0;
  const failed = summary?.failed ?? 0;
  const pct = (n: number) => (total > 0 ? `${(n / total) * 100}%` : "0%");
  return (
    <div
      className={cn("h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-800", className)}
      role="progressbar"
      aria-valuenow={passed}
      aria-valuemin={0}
      aria-valuemax={total}
      aria-label={`${passed} of ${total} release gates passed`}
    >
      <div className="flex h-full w-full">
        <div
          className="h-full rounded-l-full bg-emerald-500 transition-all duration-500"
          style={{ width: pct(passed) }}
        />
        <div className="h-full bg-destructive transition-all duration-500" style={{ width: pct(failed) }} />
        <div className="h-full bg-amber-500/80" style={{ width: pct(total - passed - failed) }} />
      </div>
    </div>
  );
}
