"use client";

// ─── Release CI gates section (Benchmark view) ───────────────────────────────
// The benchmark corpus is the scanner's CI (spec §6): every agent release must
// pass its benchmark slice — detection ≥ 90% AND FP < 2% — before its
// registry publish is unlocked. A slice regression below SLO blocks the
// release. Fed by GET /api/ci-gates (30s poll) + POST /api/ci-gates/evaluate.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { AlertCircle, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { cn, timeAgo } from "@/lib/swarm/format";
import { api, type CiEvaluateResponse } from "@/lib/swarm/types";
import { useCiGates } from "./use-ci-gates";
import {
  GatesProgressBar,
  GateStatusBadge,
  RegistryPublishBadge,
  registryPublishState,
} from "./gate-status";

export function CiGatesSection() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data, isLoading, error, refetch, isRefetching } = useCiGates();

  const evaluateMutation = useMutation({
    mutationFn: () => api<CiEvaluateResponse>("/api/ci-gates/evaluate", { method: "POST" }),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["ci-gates"] });
      toast({
        title: `CI gates re-evaluated — ${res.changed} changed`,
        description: `${res.summary.passed}/${res.summary.total} gates passed · registry publish ${registryPublishState(res.summary)}`,
        variant: res.summary.failed > 0 ? "destructive" : "default",
      });
    },
    onError: (err: Error) => {
      toast({
        title: "CI gate evaluation failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  const gates = data?.gates ?? [];
  const summary = data?.summary;
  const publish = summary ? registryPublishState(summary) : "pending";

  return (
    <Card className="rounded-xl">
      <CardHeader className="px-4 sm:px-5">
        <CardTitle className="flex flex-wrap items-center justify-between gap-3 text-sm">
          <span className="flex items-center gap-2.5">
            Release CI gates
            {summary && (
              <span className="font-mono text-[11px] font-normal text-muted-foreground">
                {summary.total} agent releases
              </span>
            )}
          </span>
          <Button
            size="sm"
            variant="outline"
            onClick={() => evaluateMutation.mutate()}
            disabled={evaluateMutation.isPending}
            className="gap-1.5"
          >
            {evaluateMutation.isPending ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                Evaluating…
              </>
            ) : (
              <>
                <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                Re-evaluate gates
              </>
            )}
          </Button>
        </CardTitle>
        <CardDescription className="text-xs">
          The corpus is the CI — an agent&apos;s registry release is blocked until its latest
          benchmark slice passes detection ≥ 90% and FP &lt; 2% (spec §6)
        </CardDescription>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-5">
        {isLoading ? (
          <div className="space-y-2" aria-busy>
            <Skeleton className="h-11 w-full rounded-lg" />
            <Skeleton className="h-10 w-full rounded-md" />
            <Skeleton className="h-10 w-full rounded-md" />
            <Skeleton className="h-10 w-full rounded-md" />
            <Skeleton className="h-10 w-3/4 rounded-md" />
          </div>
        ) : error ? (
          <div
            role="alert"
            className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-6 py-8 text-center"
          >
            <AlertCircle className="h-5 w-5 text-destructive" aria-hidden />
            <div>
              <p className="text-sm font-medium">Failed to load CI gates</p>
              <p className="mt-1 max-w-md text-xs break-words text-muted-foreground">
                {error instanceof Error ? error.message : "Control plane unreachable"}
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void refetch()}
              disabled={isRefetching}
              className="gap-2"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", isRefetching && "animate-spin")} aria-hidden />
              {isRefetching ? "Retrying…" : "Retry"}
            </Button>
          </div>
        ) : gates.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed bg-card/30 px-6 py-10 text-center">
            <ShieldCheck className="h-5 w-5 text-muted-foreground" aria-hidden />
            <p className="text-sm font-medium text-zinc-300">No release gates yet</p>
            <p className="max-w-md text-xs text-muted-foreground">
              Execute the benchmark suite above to establish a baseline — every agent release is
              gated on its slice (detection ≥ 90%, FP &lt; 2%).
            </p>
          </div>
        ) : (
          <>
            {/* summary strip: X / 15 passed + publish state */}
            <div className="mb-4 flex flex-col gap-3 rounded-lg border border-zinc-800 bg-card/60 px-4 py-3 sm:flex-row sm:items-center">
              <span className="font-mono text-sm">
                <span className={publish === "unlocked" ? "text-emerald-400" : "text-zinc-200"}>
                  {summary?.passed ?? 0}
                </span>
                <span className="text-zinc-500"> / {summary?.total ?? 0} gates passed</span>
              </span>
              <GatesProgressBar summary={summary} />
              <RegistryPublishBadge state={publish} />
            </div>

            {/* per-agent gate table */}
            <div className="max-h-[430px] overflow-x-auto overflow-y-auto swarm-scroll">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 z-10 bg-card">
                  <tr className="border-b text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="px-3 py-2 font-medium">Agent release</th>
                    <th className="px-2 py-2 font-medium">Gate</th>
                    <th className="px-3 py-2 font-medium">Detection</th>
                    <th className="px-2 py-2 text-right font-medium">FP rate</th>
                    <th className="px-2 py-2 text-right font-medium">Verdict</th>
                    <th className="px-3 py-2 font-medium">Note</th>
                  </tr>
                </thead>
                <tbody>
                  {gates.map((g, i) => {
                    const running = g.status === "running";
                    const detOk = g.detectionRate >= 90;
                    const fpBad = g.fpRate >= 2;
                    return (
                      <motion.tr
                        key={g.id}
                        initial={{ opacity: 0, x: -6 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.2, delay: Math.min(i * 0.03, 0.4) }}
                        className="border-b border-border/50 last:border-0 odd:bg-muted/15 hover:bg-muted/40"
                      >
                        <td className="px-3 py-2">
                          <div className="font-mono text-[11px] text-zinc-200">{g.agentName}</div>
                          <div className="font-mono text-[10px] text-zinc-500">{g.releaseTag}</div>
                        </td>
                        <td className="px-2 py-2">
                          <GateStatusBadge status={g.status} />
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-20 overflow-hidden rounded-full bg-muted">
                              <div
                                className={cn(
                                  "h-full rounded-full",
                                  running ? "bg-zinc-600" : detOk ? "bg-emerald-500" : "bg-destructive"
                                )}
                                style={{ width: `${Math.min(100, g.detectionRate)}%` }}
                              />
                            </div>
                            <span
                              className={cn(
                                "font-mono text-[11px] tabular-nums",
                                running ? "text-zinc-500" : detOk ? "text-zinc-400" : "text-destructive"
                              )}
                            >
                              {g.detectionRate.toFixed(1)}%
                            </span>
                          </div>
                        </td>
                        <td className="px-2 py-2 text-right">
                          <span
                            className={cn(
                              "font-mono text-[11px] tabular-nums",
                              fpBad ? "text-amber-400" : "text-zinc-400"
                            )}
                          >
                            {g.fpRate.toFixed(1)}%
                          </span>
                        </td>
                        <td className="px-2 py-2 text-right font-mono text-[10px] tabular-nums text-zinc-500">
                          {timeAgo(g.verdictAt)}
                        </td>
                        <td className="max-w-[320px] px-3 py-2 text-[10px] leading-relaxed text-zinc-400">
                          {g.note}
                        </td>
                      </motion.tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
