"use client";

// ─── ScanDetailView — DAG pipeline, findings, chains, live timeline ──────────

import { useEffect, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  ArrowLeft,
  BadgeCheck,
  Check,
  Copy,
  Globe,
  Loader2,
  Network,
  RotateCw,
  Square,
  Siren,
  Terminal,
  Timer,
  TriangleAlert,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
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
import { useSwarmUi } from "@/lib/swarm/ui-store";
import {
  BAND_STYLES,
  SEVERITY_STYLES,
  cn,
  formatDuration,
  truncateMiddle,
} from "@/lib/swarm/format";
import {
  api,
  type AgentRun,
  type EngineAgentUpdate,
  type EngineKillResponse,
  type EventLogItem,
  type ScanDetail,
} from "@/lib/swarm/types";
import { useEngineSub } from "@/components/swarm/overview/use-engine-sub";
import { EventFeedList, toEventItem } from "@/components/swarm/overview/event-feed";
import { AnimatedNumber } from "@/components/swarm/overview/animated-number";
import {
  isScanActive,
  PolicyTierChip,
  ProfileChip,
  ProgressBar,
  ScanStatusBadge,
} from "./status-badge";
import { AgentPipeline } from "./agent-pipeline";

const EVENT_CAP = 60;

function patchAgentRuns(runs: AgentRun[], u: EngineAgentUpdate): AgentRun[] {
  const idx = runs.findIndex((r) => r.agentKey === u.agentKey);
  if (idx >= 0) {
    const next = [...runs];
    next[idx] = {
      ...next[idx],
      agentName: u.agentName,
      version: u.version,
      state: u.state,
      status: u.status,
      progress: u.progress,
      requests: u.requests,
      findings: u.findings,
      endedAt:
        u.status === "done" || u.status === "killed"
          ? (next[idx].endedAt ?? new Date().toISOString())
          : next[idx].endedAt,
    };
    return next;
  }
  return [
    ...runs,
    {
      id: `live-${u.agentKey}`,
      scanId: u.scanId,
      agentKey: u.agentKey,
      agentName: u.agentName,
      version: u.version,
      state: u.state,
      status: u.status,
      progress: u.progress,
      requests: u.requests,
      findings: u.findings,
      startedAt: new Date().toISOString(),
      endedAt: null,
    },
  ];
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable — silent no-op
    }
  };
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className="h-6 w-6 shrink-0"
      onClick={copy}
      aria-label={label}
    >
      {copied ? (
        <Check className="h-3 w-3 text-emerald-500" aria-hidden />
      ) : (
        <Copy className="h-3 w-3" aria-hidden />
      )}
    </Button>
  );
}

function HeaderStat({
  label,
  children,
  title,
}: {
  label: string;
  children: ReactNode;
  title?: string;
}) {
  return (
    <div className="min-w-[76px] text-right" title={title}>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="font-mono text-lg font-semibold leading-tight text-foreground">
        {children}
      </div>
    </div>
  );
}

export function ScanDetailView({ scanId }: { scanId: string }) {
  const closeScan = useSwarmUi((s) => s.closeScan);
  const setView = useSwarmUi((s) => s.setView);
  const openFinding = useSwarmUi((s) => s.openFinding);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [killing, setKilling] = useState(false);
  const [, setTick] = useState(0); // forces duration re-render each second

  const query = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api<ScanDetail>(`/api/scans/${scanId}`),
    refetchInterval: (q) => (isScanActive(q.state.data?.status) ? 3000 : false),
  });

  const scan = query.data;
  const running = isScanActive(scan?.status);

  // Live duration ticker while the scan is active.
  useEffect(() => {
    if (!running) return;
    const interval = window.setInterval(() => setTick((t) => t + 1), 1000);
    return () => window.clearInterval(interval);
  }, [running]);

  // ── Live socket patches (avoid refetch storms) ────────────────────────────
  useEngineSub("agent:update", (u) => {
    if (u.scanId !== scanId) return;
    queryClient.setQueryData<ScanDetail>(["scan", scanId], (old) =>
      old ? { ...old, agentRuns: patchAgentRuns(old.agentRuns, u) } : old
    );
  });

  useEngineSub("scan:update", (u) => {
    if (u.scanId !== scanId) return;
    queryClient.setQueryData<ScanDetail>(["scan", scanId], (old) =>
      old
        ? { ...old, status: u.status, progress: u.progress, requestCount: u.requestCount }
        : old
    );
    if (u.status === "completed" || u.status === "killed" || u.status === "failed") {
      void queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["scans"] });
    }
  });

  useEngineSub("finding:new", (e) => {
    if (e.scanId !== scanId) return;
    queryClient.setQueryData<ScanDetail>(["scan", scanId], (old) =>
      old ? { ...old, findings: [e.finding, ...old.findings] } : old
    );
  });

  useEngineSub("event:new", (e) => {
    if (e.scanId !== scanId) return;
    queryClient.setQueryData<ScanDetail>(["scan", scanId], (old) => {
      if (!old) return old;
      const item = toEventItem(e);
      const dedupeKey = `${item.type}|${item.message}|${item.createdAt}`;
      const isDupe = old.events.some(
        (ev) => `${ev.type}|${ev.message}|${ev.createdAt}` === dedupeKey
      );
      if (isDupe) return old;
      return { ...old, events: [item, ...old.events].slice(0, EVENT_CAP) };
    });
  });

  const killScan = async () => {
    setKilling(true);
    try {
      const res = await api<EngineKillResponse>(`/api/scans/${scanId}/kill`, {
        method: "POST",
      });
      toast({
        title: `SIGKILL propagated in ${res.latencyMs}ms`,
        description:
          res.message || "All in-flight probes terminated. Evidence preserved in WORM ledger.",
        variant: "destructive",
      });
    } catch (err) {
      toast({
        title: "Kill failed",
        description: err instanceof Error ? err.message : "Engine unreachable",
        variant: "destructive",
      });
    } finally {
      setKilling(false);
    }
  };

  if (query.isError) {
    return (
      <div className="px-4 py-6 mx-auto w-full max-w-[1600px] lg:px-6">
        <Button
          variant="ghost"
          size="sm"
          className="mb-4 gap-1.5 text-muted-foreground"
          onClick={closeScan}
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
          Back to scans
        </Button>
        <Alert variant="destructive" role="alert">
          <TriangleAlert className="h-4 w-4" aria-hidden />
          <AlertTitle>Failed to load scan detail</AlertTitle>
          <AlertDescription className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-xs">
              {query.error instanceof Error
                ? query.error.message
                : "Control plane unreachable"}
            </span>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => void query.refetch()}
            >
              <RotateCw className="h-3.5 w-3.5" aria-hidden />
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (query.isPending || !scan) {
    return (
      <div
        className="px-4 py-6 mx-auto w-full max-w-[1600px] lg:px-6"
        aria-busy="true"
        aria-label="Loading scan detail"
      >
        <Skeleton className="mb-4 h-8 w-36 rounded-md" />
        <Skeleton className="mb-6 h-[150px] rounded-xl" />
        <div className="grid gap-6 xl:grid-cols-3">
          <div className="space-y-4 xl:col-span-2">
            <Skeleton className="h-10 w-64 rounded-md" />
            <Skeleton className="h-24 rounded-lg" />
            <Skeleton className="h-24 rounded-lg" />
            <Skeleton className="h-24 rounded-lg" />
          </div>
          <Skeleton className="h-[480px] rounded-xl" />
        </div>
      </div>
    );
  }

  const agentsDone = scan.agentRuns.filter((r) => r.status === "done").length;
  const sortedEvents = [...scan.events].sort((a, b) =>
    (b.createdAt ?? "").localeCompare(a.createdAt ?? "")
  );

  return (
    <div className="px-4 py-6 mx-auto w-full max-w-[1600px] lg:px-6">
      <Button
        variant="ghost"
        size="sm"
        className="mb-4 gap-1.5 text-muted-foreground hover:text-foreground"
        onClick={closeScan}
        aria-label="Back to scan list"
      >
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
        Back to scans
      </Button>

      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="space-y-6"
      >
        {/* ── Header ─────────────────────────────────────────────────────────── */}
        <Card className="gap-4 rounded-xl px-4 py-4 sm:px-6">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0 flex-1 space-y-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <ScanStatusBadge status={scan.status} />
                <ProfileChip profile={scan.profile} />
                <PolicyTierChip tier={scan.policyTier} />
              </div>
              <div className="flex min-w-0 items-center gap-1.5">
                <Globe className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
                <h2
                  className="truncate font-mono text-lg font-semibold tracking-tight"
                  title={scan.target}
                >
                  {scan.target}
                </h2>
                <CopyButton text={scan.target} label="Copy target URL" />
              </div>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
                <span>seed</span>
                <code className="font-mono text-zinc-400">
                  {scan.seed ? truncateMiddle(scan.seed, 26) : "—"}
                </code>
                {scan.seed && <CopyButton text={scan.seed} label="Copy seed" />}
                <span aria-hidden>·</span>
                <span>plan</span>
                <code className="font-mono text-zinc-400">DAG-{scan.id.slice(0, 8)}</code>
                <span aria-hidden>·</span>
                <span>
                  {agentsDone}/{scan.agentCount || scan.agentRuns.length} agents done
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-start gap-5 lg:justify-end">
              <HeaderStat label="Requests" title="Total requests dispatched">
                <AnimatedNumber value={scan.requestCount} />
              </HeaderStat>
              <HeaderStat label="Duration" title={running ? "live" : "final"}>
                <span className="inline-flex items-center gap-1">
                  <Timer className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                  {running ? (
                    formatDuration(scan.startedAt, null)
                  ) : (
                    formatDuration(scan.startedAt, scan.completedAt)
                  )}
                </span>
              </HeaderStat>
              <HeaderStat label="Findings" title="Findings emitted by this scan">
                <span className={cn(scan.findings.length > 0 && "text-amber-400")}>
                  {scan.findings.length}
                </span>
              </HeaderStat>
              {running && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      variant="destructive"
                      size="sm"
                      disabled={killing}
                      className="gap-1.5"
                      aria-label="Kill this scan"
                    >
                      {killing ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                      ) : (
                        <Square className="h-3.5 w-3.5 fill-current" aria-hidden />
                      )}
                      Kill Scan
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle className="font-mono text-base">
                        Kill {truncateMiddle(scan.target, 40)}?
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        SIGKILL propagates to every in-flight probe within 500 ms.
                        The scan is marked <code>killed</code>; collected evidence is
                        preserved in the WORM ledger.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        onClick={(e) => {
                          e.preventDefault();
                          void killScan();
                        }}
                      >
                        {killing ? "Killing…" : "Kill scan"}
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
              <span>Overall progress</span>
              <span className="font-mono">{Math.round(scan.progress)}%</span>
            </div>
            <ProgressBar value={scan.progress} active={running} />
          </div>
        </Card>

        {/* ── Two-column: pipeline+findings+chains · timeline ──────────────── */}
        <div className="grid items-start gap-6 xl:grid-cols-3">
          <div className="space-y-6 xl:col-span-2">
            <Card className="rounded-xl px-4 py-4 sm:px-6">
              <CardHeader className="px-0">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Loader2
                    className={cn(
                      "h-4 w-4 text-primary",
                      running ? "animate-spin" : "opacity-40"
                    )}
                    aria-hidden
                  />
                  Agent Pipeline
                </CardTitle>
                <CardDescription className="text-xs">
                  15-agent DAG across 6 execution stages · FSM state per agent
                </CardDescription>
              </CardHeader>
              <CardContent className="px-0 pb-1">
                <AgentPipeline scanId={scan.id} agentRuns={scan.agentRuns} />
              </CardContent>
            </Card>

            {/* Findings */}
            <Card className="rounded-xl px-4 py-4 sm:px-6">
              <CardHeader className="px-0">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Siren className="h-4 w-4 text-primary" aria-hidden />
                  Findings
                  <Badge
                    variant="outline"
                    className="font-mono text-[10px] font-normal text-muted-foreground"
                  >
                    {scan.findings.length}
                  </Badge>
                </CardTitle>
                <CardDescription className="text-xs">
                  Emitted by this scan · click to inspect Bayesian evidence
                </CardDescription>
              </CardHeader>
              <CardContent className="px-0 pb-1">
                {scan.findings.length === 0 ? (
                  <p className="py-8 text-center font-mono text-xs text-muted-foreground">
                    No findings emitted
                  </p>
                ) : (
                  <div className="max-h-96 overflow-y-auto swarm-scroll pr-1">
                    <ul className="space-y-0.5">
                      {scan.findings.map((f) => {
                        const sev = SEVERITY_STYLES[f.severity];
                        return (
                          <li key={f.id}>
                            <button
                              type="button"
                              onClick={() => {
                                setView("findings");
                                openFinding(f.id);
                              }}
                              className="group grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 rounded-md px-2 py-2 text-left transition-colors hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                              aria-label={`Open finding: ${f.title}`}
                            >
                              <span
                                className={cn("h-2 w-2 shrink-0 rounded-full", sev.dot)}
                                title={sev.label}
                                aria-hidden
                              />
                              <span className="min-w-0">
                                <span className="block truncate text-[13px] font-medium text-zinc-200 group-hover:text-foreground">
                                  {f.title}
                                </span>
                                <span className="block truncate font-mono text-[11px] text-muted-foreground">
                                  {f.agentKey} · {f.target}
                                  {f.endpoint ? f.endpoint : ""}
                                </span>
                              </span>
                              <span className="flex shrink-0 items-center gap-2">
                                <span
                                  className={cn(
                                    "rounded border px-1.5 py-px text-[10px] font-semibold",
                                    BAND_STYLES[f.band].badge
                                  )}
                                  title={BAND_STYLES[f.band].hint}
                                >
                                  {f.confidence}
                                </span>
                                <span className={cn("text-[10px] font-semibold uppercase", sev.text)}>
                                  {sev.label}
                                </span>
                              </span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Attack chains */}
            {scan.chains.length > 0 && (
              <Card className="rounded-xl px-4 py-4 sm:px-6">
                <CardHeader className="px-0">
                  <CardTitle className="flex items-center gap-2 text-sm">
                    <Network className="h-4 w-4 text-primary" aria-hidden />
                    Attack Chains
                  </CardTitle>
                  <CardDescription className="text-xs">
                    CorrelatorAgent exploitation paths with PoC plan gates
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 px-0 pb-1">
                  {scan.chains.map((chain) => {
                    const sev = SEVERITY_STYLES[chain.severity];
                    return (
                      <div
                        key={chain.id}
                        className="flex flex-wrap items-center gap-3 rounded-lg border bg-muted/30 px-3 py-2.5"
                      >
                        <span
                          className={cn(
                            "rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
                            sev.badge
                          )}
                        >
                          {sev.label}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-zinc-200">
                          {chain.name}
                        </span>
                        <span
                          className={cn(
                            "flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold",
                            chain.verified
                              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                              : "border-zinc-600 bg-zinc-700/20 text-zinc-400"
                          )}
                          title={chain.verified ? "Chain machine-verified" : "Awaiting verification"}
                        >
                          {chain.verified ? (
                            <BadgeCheck className="h-3 w-3" aria-hidden />
                          ) : (
                            <TriangleAlert className="h-3 w-3" aria-hidden />
                          )}
                          {chain.verified ? "verified" : "unverified"}
                        </span>
                        <span className="shrink-0 font-mono text-[10px] text-zinc-500">
                          step {chain.currentStep}/{chain.steps.length}
                        </span>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 gap-1.5 text-[11px]"
                          onClick={() => setView("attack-graph")}
                        >
                          Open in Attack Graph
                        </Button>
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            )}
          </div>

          {/* Timeline */}
          <Card className="rounded-xl px-4 py-4 sm:px-5 xl:sticky xl:top-20">
            <CardHeader className="px-0">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Terminal className="h-4 w-4 text-primary" aria-hidden />
                Event Timeline
              </CardTitle>
              <CardDescription className="flex items-center gap-2 text-xs">
                <span
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded border px-1.5 py-px font-mono text-[10px] font-semibold uppercase tracking-wider",
                    running
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-zinc-700 text-zinc-500"
                  )}
                >
                  <span
                    className={cn(
                      "h-1.5 w-1.5 rounded-full",
                      running ? "bg-primary swarm-pulse" : "bg-zinc-600"
                    )}
                    aria-hidden
                  />
                  {running ? "STREAMING" : "IDLE"}
                </span>
                <span className="font-mono text-zinc-500">
                  {sortedEvents.length} events
                </span>
              </CardDescription>
            </CardHeader>
            <CardContent className="px-0">
              <EventFeedList
                events={sortedEvents}
                maxHeightClass="max-h-[640px] xl:max-h-[calc(100vh-260px)]"
                emptyText="no events for this scan yet"
              />
            </CardContent>
          </Card>
        </div>
      </motion.div>
    </div>
  );
}
