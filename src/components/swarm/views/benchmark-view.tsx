"use client";

// ─── Benchmark Corpus view (spec §6 — "it's your CI") ────────────────────────
// 500-case FN regression suite: corpus composition, per-agent conformance
// slices, SLO gates (detection ≥ 90%, FP < 2%), run history.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  FlaskConical,
  Loader2,
  Play,
  Target,
  XCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  api,
  type BenchmarkRunResponse,
  type BenchmarkSummaryResponse,
} from "@/lib/swarm/types";
import type { AgentSliceStats } from "@/lib/swarm/benchmark";
import { SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import { CiGatesSection } from "@/components/swarm/ci-gates/ci-gates-section";

type Summary = BenchmarkSummaryResponse & { slices: AgentSliceStats[] };

function Pct({ value, className }: { value: number; className?: string }) {
  return (
    <span className={cn("font-mono tabular-nums", className)}>
      {(value * 100).toFixed(1)}%
    </span>
  );
}

export function BenchmarkView() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ["benchmark"],
    queryFn: () => api<Summary>("/api/benchmark"),
  });

  const runMutation = useMutation({
    mutationFn: () => api<BenchmarkRunResponse>("/api/benchmark/run", { method: "POST" }),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["benchmark"] });
      toast({
        title: res.aggregate.sloMet ? "Benchmark suite passed" : "SLO regression detected",
        description: `Detection ${(res.aggregate.detectionRate * 100).toFixed(1)}% · FP ${(res.aggregate.fpRate * 100).toFixed(2)}% · ${(res.aggregate.durationMs / 1000).toFixed(1)}s · seed ${res.seed}`,
        variant: res.aggregate.sloMet ? "default" : "destructive",
      });
    },
    onError: (err: Error) => {
      toast({
        title: "Benchmark run failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  const latest = data?.latestRun;
  const slo = data?.slo;

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px] space-y-4">
      {/* Hero: corpus + SLO gates */}
      <div className="grid gap-3 lg:grid-cols-[1fr_auto]">
        <Card className="rounded-xl px-4 py-4 sm:px-5">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-primary/30 bg-primary/10">
                <FlaskConical className="h-5 w-5 text-primary" aria-hidden />
              </div>
              <div>
                <div className="font-mono text-2xl font-semibold leading-none tabular-nums">
                  {data?.totalCases ?? "—"}
                </div>
                <div className="text-[11px] text-muted-foreground">
                  curated cases · {data?.agents ?? 15} agent slices
                </div>
              </div>
            </div>
            <Separator orientation="vertical" className="hidden h-10 sm:block" />
            <div className="flex flex-wrap gap-x-5 gap-y-2 text-[11px] text-muted-foreground">
              {(data?.byDifficulty &&
                (Object.entries(data.byDifficulty) as [string, number][]).map(([k, v]) => (
                  <span key={k}>
                    <span className="font-mono text-sm font-semibold text-zinc-200 tabular-nums">{v}</span>{" "}
                    {k}
                  </span>
                ))) ?? null}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {data?.bySeverity
                ? Object.entries(data.bySeverity)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 5)
                    .map(([sev, count]) => (
                      <Badge
                        key={sev}
                        variant="outline"
                        className={cn("gap-1 font-mono text-[10px]", SEVERITY_STYLES[sev as keyof typeof SEVERITY_STYLES]?.badge)}
                      >
                        <span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_STYLES[sev as keyof typeof SEVERITY_STYLES]?.dot)} aria-hidden />
                        {count} {sev}
                      </Badge>
                    ))
                : null}
            </div>
          </div>
        </Card>

        <Card className="flex items-center gap-4 rounded-xl px-4 py-4 sm:px-5">
          {slo && latest && (
            <>
              <div className="text-center">
                <div
                  className={cn(
                    "font-mono text-2xl font-semibold tabular-nums",
                    latest.aggregate.detectionRate >= slo.fnTarget ? "text-emerald-400" : "text-destructive"
                  )}
                >
                  {(latest.aggregate.detectionRate * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-muted-foreground">detection ≥ 90%</div>
              </div>
              <div className="text-center">
                <div
                  className={cn(
                    "font-mono text-2xl font-semibold tabular-nums",
                    latest.aggregate.fpRate < slo.fpTarget ? "text-emerald-400" : "text-destructive"
                  )}
                >
                  {(latest.aggregate.fpRate * 100).toFixed(2)}%
                </div>
                <div className="text-[10px] text-muted-foreground">FP &lt; 2%</div>
              </div>
            </>
          )}
          <Button
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending}
            className="gap-2"
            size="lg"
          >
            {runMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                Executing suite…
              </>
            ) : (
              <>
                <Play className="h-4 w-4" aria-hidden />
                Run suite
              </>
            )}
          </Button>
        </Card>
      </div>

      {isLoading && (
        <div className="grid gap-3 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-40 animate-pulse rounded-xl bg-muted/40" />
          ))}
        </div>
      )}

      {error && (
        <Card className="rounded-xl border-destructive/40 px-5 py-4 text-sm text-destructive">
          Failed to load benchmark summary — {error.message}
        </Card>
      )}

      {latest && (
        <Card className="rounded-xl">
          <CardHeader className="px-4 sm:px-5">
            <CardTitle className="flex flex-wrap items-center gap-2.5 text-sm">
              Latest suite run
              <Badge
                variant="outline"
                className={cn(
                  "gap-1 font-mono text-[10px]",
                  latest.aggregate.sloMet
                    ? "border-emerald-500/40 text-emerald-400"
                    : "border-destructive/40 text-destructive"
                )}
              >
                {latest.aggregate.sloMet ? (
                  <>
                    <CheckCircle2 className="h-3 w-3" aria-hidden /> SLO MET
                  </>
                ) : (
                  <>
                    <AlertTriangle className="h-3 w-3" aria-hidden /> SLO REGRESSION
                  </>
                )}
              </Badge>
              <span className="font-mono text-[11px] font-normal text-muted-foreground">
                seed {latest.seed} · {latest.rows.length} agents
              </span>
            </CardTitle>
            <CardDescription className="text-xs">
              {latest.aggregate.passed}/{latest.aggregate.total} cases detected ·{" "}
              {latest.aggregate.failed} false negatives · aggregate{" "}
              <Pct value={latest.aggregate.fnRate} /> FN ·{" "}
              {(latest.aggregate.durationMs / 1000).toFixed(1)}s wall time
            </CardDescription>
          </CardHeader>
          <CardContent className="px-2 pb-4 sm:px-4">
            <div className="max-h-[430px] overflow-y-auto swarm-scroll">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 z-10 bg-card">
                  <tr className="border-b text-[10px] uppercase tracking-wider text-muted-foreground">
                    <th className="px-3 py-2 font-medium">Agent slice</th>
                    <th className="px-2 py-2 text-right font-medium">Cases</th>
                    <th className="px-2 py-2 text-right font-medium">Passed</th>
                    <th className="px-2 py-2 text-right font-medium">FN</th>
                    <th className="px-3 py-2 font-medium">Detection</th>
                    <th className="px-2 py-2 text-right font-medium">FP rate</th>
                  </tr>
                </thead>
                <tbody>
                  {latest.rows.map((r, i) => {
                    const detection = r.total > 0 ? r.passed / r.total : 0;
                    const fnBad = detection < (slo?.fnTarget ?? 0.9);
                    return (
                      <motion.tr
                        key={r.id}
                        initial={{ opacity: 0, x: -6 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.2, delay: Math.min(i * 0.03, 0.4) }}
                        className="border-b border-border/50 last:border-0 odd:bg-muted/15 hover:bg-muted/40"
                      >
                        <td className="px-3 py-2 font-mono text-[11px] text-zinc-200">{r.agentName}</td>
                        <td className="px-2 py-2 text-right font-mono tabular-nums">{r.total}</td>
                        <td className="px-2 py-2 text-right font-mono tabular-nums text-emerald-400">{r.passed}</td>
                        <td className="px-2 py-2 text-right font-mono tabular-nums">
                          <span className={cn(r.failed > 0 && (fnBad ? "text-destructive" : "text-amber-400"))}>
                            {r.failed}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-24 overflow-hidden rounded-full bg-muted">
                              <div
                                className={cn(
                                  "h-full rounded-full",
                                  detection >= 0.95
                                    ? "bg-emerald-500"
                                    : detection >= 0.9
                                      ? "bg-primary"
                                      : "bg-destructive"
                                )}
                                style={{ width: `${detection * 100}%` }}
                              />
                            </div>
                            <Pct value={detection} className="text-[11px] text-zinc-400" />
                          </div>
                        </td>
                        <td className="px-2 py-2 text-right">
                          <Pct
                            value={r.fpRate}
                            className={cn(
                              "text-[11px]",
                              r.fpRate < (slo?.fpTarget ?? 0.02) ? "text-zinc-400" : "text-destructive"
                            )}
                          />
                        </td>
                      </motion.tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Release CI gates — corpus verdicts gate agent-registry publishes */}
      <CiGatesSection />

      {/* Corpus composition + history */}
      <div className="grid gap-3 lg:grid-cols-2">
        <Card className="rounded-xl">
          <CardHeader className="px-4 sm:px-5">
            <CardTitle className="text-sm">Corpus composition — agent slices</CardTitle>
            <CardDescription className="text-xs">
              Cases distributed per agent · two-technique confirmation pairs enforced
            </CardDescription>
          </CardHeader>
          <CardContent className="px-2 pb-4 sm:px-4">
            <div className="max-h-72 overflow-y-auto swarm-scroll">
              <ul className="space-y-1">
                {data?.slices.map((s, i) => (
                  <motion.li
                    key={s.agentKey}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.2, delay: Math.min(i * 0.025, 0.35) }}
                    className="grid grid-cols-[1fr_auto_auto] items-center gap-3 rounded-md px-2 py-1.5 hover:bg-muted/30"
                  >
                    <span className="font-mono text-[11px] text-zinc-300">{s.agentName}</span>
                    <div className="flex h-1.5 w-32 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full bg-primary/70"
                        style={{ width: `${(s.total / 80) * 100}%` }}
                      />
                    </div>
                    <span className="font-mono text-[11px] tabular-nums text-zinc-400">
                      {s.total} cases
                    </span>
                  </motion.li>
                ))}
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card className="rounded-xl">
          <CardHeader className="px-4 sm:px-5">
            <CardTitle className="text-sm">Run history — detection trend</CardTitle>
            <CardDescription className="text-xs">
              Every agent release must pass its benchmark slice in CI
            </CardDescription>
          </CardHeader>
          <CardContent className="px-4 pb-4 sm:px-5">
            {data && data.history.length > 0 ? (
              <div className="space-y-1.5">
                {data.history.map((h) => (
                  <div
                    key={h.runKey}
                    className="flex items-center gap-3 rounded-md border border-border/60 px-3 py-2"
                  >
                    {h.sloMet ? (
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-400" aria-hidden />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 shrink-0 text-destructive" aria-hidden />
                    )}
                    <span className="font-mono text-[10px] text-zinc-500">
                      {new Date(h.createdAt).toLocaleString("en-GB", {
                        day: "2-digit",
                        month: "short",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                    <div className="ml-auto flex items-center gap-3">
                      <Pct
                        value={h.detectionRate}
                        className={cn(
                          "text-[11px]",
                          h.detectionRate >= 0.9 ? "text-emerald-400" : "text-destructive"
                        )}
                      />
                      <Pct
                        value={h.fpRate}
                        className={cn(
                          "text-[11px]",
                          h.fpRate < 0.02 ? "text-zinc-400" : "text-destructive"
                        )}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex h-40 flex-col items-center justify-center gap-2 text-center">
                <Target className="h-5 w-5 text-muted-foreground" aria-hidden />
                <p className="font-mono text-xs text-muted-foreground">no runs recorded yet</p>
                <p className="max-w-xs text-[11px] text-zinc-600">
                  Execute the suite to establish a baseline — the corpus is the CI gate
                  for agent releases (FN ≥ 90% detection, FP &lt; 2%)
                </p>
              </div>
            )}
            {data && data.history.length > 0 && (
              <p className="mt-3 flex items-center gap-1.5 text-[10px] text-zinc-600">
                <Clock3 className="h-3 w-3" aria-hidden />
                newest first · detection / FP columns · gate: ≥ 90% · &lt; 2%
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Source mapping footer */}
      {data && data.bySource.length > 0 && (
        <Card className="rounded-xl px-4 py-4 sm:px-5">
          <CardTitle className="mb-3 text-sm">Source labs mapping</CardTitle>
          <div className="flex flex-wrap gap-1.5">
            {data.bySource.map((s) => (
              <Badge
                key={s.source}
                variant="outline"
                className="bg-muted/40 font-mono text-[10px] text-zinc-400"
              >
                {s.source} <span className="text-zinc-500">×{s.count}</span>
              </Badge>
            ))}
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-zinc-600">
            Mapped from PortSwigger Web Security Academy, DVWA, flAWS.cloud,
            HackerOne disclosed reports, OWASP benchmark, ysoserial/phpggc gadget
            corpora and synthetic chain/persistence corpora. Case difficulty mixes
            basic/intermediate/advanced 3:4:3 per slice.
          </p>
        </Card>
      )}
    </div>
  );
}
