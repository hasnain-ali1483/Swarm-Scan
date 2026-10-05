"use client";

// ─── Release gates strip (Integrations view) ─────────────────────────────────
// Compact live CI-gate state for the CI/CD story: how many agent releases are
// unlocked vs blocked by the benchmark corpus. The detailed surface is the
// Benchmark view's "Release CI gates" section (navigate via setView).

import { ArrowRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/swarm/format";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { useCiGates } from "./use-ci-gates";
import { GatesProgressBar, registryPublishState } from "./gate-status";

export function CiGatesStrip() {
  const setView = useSwarmUi((s) => s.setView);
  const { data, isLoading, isError } = useCiGates();

  const summary = data?.summary;
  const publish = summary ? registryPublishState(summary) : "pending";
  const stateText =
    publish === "unlocked" ? "text-emerald-400" : publish === "blocked" ? "text-destructive" : "text-amber-400";

  return (
    <div className="mt-3 flex flex-col gap-3 rounded-lg border border-zinc-800 bg-card/60 px-4 py-3 sm:flex-row sm:items-center">
      <div className="flex items-center gap-2.5">
        <ShieldCheck
          className={cn(
            "h-4 w-4 shrink-0",
            isLoading || isError ? "text-zinc-500" : publish === "unlocked" ? "text-emerald-400" : publish === "blocked" ? "text-destructive" : "text-amber-400"
          )}
          aria-hidden
        />
        <span className="font-mono text-sm">
          {isLoading ? (
            <span className="text-zinc-500">Release gates syncing…</span>
          ) : isError ? (
            <span className="text-zinc-500">Release gates unavailable</span>
          ) : (
            <>
              <span className={stateText}>{summary?.passed ?? 0}</span>
              <span className="text-zinc-500"> / {summary?.total ?? 0} gates passed · </span>
              <span className={stateText}>publish {publish}</span>
            </>
          )}
        </span>
      </div>
      {!isLoading && !isError && summary ? <GatesProgressBar summary={summary} className="hidden sm:block" /> : <div className="hidden flex-1 sm:block" />}
      <Button
        variant="outline"
        size="sm"
        onClick={() => setView("benchmark")}
        className="gap-1.5 sm:ml-auto"
      >
        View gates
        <ArrowRight className="h-3.5 w-3.5" aria-hidden />
      </Button>
    </div>
  );
}
