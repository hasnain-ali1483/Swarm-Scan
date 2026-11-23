"use client";

// ─── Finding detail: Bayesian confidence, evidence chain, PoC, actions ───────

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  ArrowLeft,
  Bug,
  Clock,
  Download,
  Loader2,
  Radar,
  RefreshCcw,
  Siren,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import {
  api,
  type Finding,
} from "@/lib/swarm/types";
import {
  BAND_STYLES,
  SEVERITY_STYLES,
  cn,
  timeAgo,
  truncateMiddle,
} from "@/lib/swarm/format";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { ConfidencePanel } from "./confidence-panel";
import { EvidenceChain } from "./evidence-chain";
import { PocCard } from "./poc-card";
import { RemediationCard } from "./remediation-card";
import { BlockSkeleton, ErrorState } from "./states";
import { downloadJson } from "./browser-utils";

export function FindingDetail({ findingId }: { findingId: string }) {
  const closeFinding = useSwarmUi((s) => s.closeFinding);
  const openScan = useSwarmUi((s) => s.openScan);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: finding, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api<Finding>(`/api/findings/${findingId}`),
  });

  const verifyMutation = useMutation({
    mutationFn: () => api<Partial<Finding>>(`/api/findings/${findingId}/verify`, { method: "POST" }),
    onSuccess: (res) => {
      if (res && typeof res === "object" && typeof res.confidence === "number") {
        // Response carries the updated finding — merge into the cache.
        queryClient.setQueryData<Finding>(["finding", findingId], (old) =>
          old ? { ...old, ...res, evidence: res.evidence ?? old.evidence } : (res as Finding)
        );
      } else {
        void queryClient.invalidateQueries({ queryKey: ["finding", findingId] });
      }
      const fresh =
        (typeof res?.confidence === "number" ? res : undefined) ??
        queryClient.getQueryData<Finding>(["finding", findingId]);
      const confidence = fresh?.confidence ?? finding?.confidence ?? 0;
      toast({
        title: "Independent re-verification passed",
        description: `Confidence updated to ${confidence}/99 — a re-verify record was appended to the evidence chain.`,
      });
    },
    onError: (err) => {
      toast({
        title: "Re-verification failed",
        description: err instanceof Error ? err.message : "Engine unreachable",
        variant: "destructive",
      });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" className="-ml-2 gap-1.5 text-muted-foreground" disabled>
          <ArrowLeft className="h-4 w-4" aria-hidden /> Back to findings
        </Button>
        <BlockSkeleton />
        <p className="sr-only" role="status">Loading finding…</p>
      </div>
    );
  }

  if (isError || !finding) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={closeFinding} className="-ml-2 gap-1.5 text-muted-foreground">
          <ArrowLeft className="h-4 w-4" aria-hidden /> Back to findings
        </Button>
        <ErrorState
          title="Failed to load finding"
          message={error instanceof Error ? error.message : "Not found"}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      </div>
    );
  }

  const evidence = [...(finding.evidence ?? [])].sort((a, b) => a.sequence - b.sequence);

  return (
    <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }} className="space-y-4">
      <Button variant="ghost" size="sm" onClick={closeFinding} className="-ml-2 gap-1.5 text-muted-foreground hover:text-foreground" aria-label="Back to findings list">
        <ArrowLeft className="h-4 w-4" aria-hidden /> Back to findings
      </Button>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className={cn("px-2 py-0.5 text-[11px] uppercase tracking-wide", SEVERITY_STYLES[finding.severity].badge)}>
            <Siren className="h-3 w-3" aria-hidden />
            {SEVERITY_STYLES[finding.severity].label}
          </Badge>
          <Badge variant="outline" className={cn("px-2 py-0.5 text-[11px]", BAND_STYLES[finding.band].badge)} title={BAND_STYLES[finding.band].hint}>
            {BAND_STYLES[finding.band].label}
          </Badge>
          {finding.cve ? (
            <Badge variant="outline" className="border-red-500/40 bg-red-500/10 px-2 py-0.5 font-mono text-[11px] text-red-400">
              <Bug className="h-3 w-3" aria-hidden />
              {finding.cve}
            </Badge>
          ) : null}
          <Badge variant="outline" className="border-zinc-700/70 bg-zinc-900/50 px-2 py-0.5 font-mono text-[11px] text-zinc-400">
            {finding.agentKey}
          </Badge>
        </div>

        <h2 className="text-xl font-semibold tracking-tight">{finding.title}</h2>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
          <span className="font-mono text-zinc-300 underline decoration-zinc-600 underline-offset-4" title={finding.target}>
            {truncateMiddle(finding.target, 48)}
          </span>
          {finding.endpoint ? (
            <span className="min-w-0 truncate font-mono text-zinc-500" title={finding.endpoint}>
              {truncateMiddle(finding.endpoint, 42)}
            </span>
          ) : null}
          <button
            type="button"
            onClick={() => openScan(finding.scanId)}
            className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700/70 bg-zinc-900/50 px-2 py-0.5 font-mono text-[11px] text-zinc-400 transition-colors hover:border-primary/50 hover:text-primary focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/40"
            aria-label={`Open originating scan ${finding.scan?.target ?? finding.scanId}`}
          >
            <Radar className="h-3 w-3" aria-hidden />
            {finding.scan?.target ? truncateMiddle(finding.scan.target, 28) : `scan ${truncateMiddle(finding.scanId, 12)}`}
          </button>
          <span className="flex items-center gap-1.5 text-zinc-500" title={new Date(finding.createdAt).toISOString()}>
            <Clock className="h-3 w-3" aria-hidden />
            first seen {timeAgo(finding.createdAt)}
          </span>
        </div>

        <p className="max-w-4xl text-sm leading-relaxed text-zinc-300">{finding.description}</p>
      </section>

      {/* ── Bayesian confidence ────────────────────────────────────────────── */}
      <ConfidencePanel finding={{ ...finding, evidence }} />

      {/* ── Autonomous Remediation & Virtual Patching ──────────────────────── */}
      <RemediationCard finding={finding} />

      {/* ── Evidence chain + PoC/actions ───────────────────────────────────── */}
      <div className="grid items-start gap-4 lg:grid-cols-3">
        <div className="min-w-0 lg:col-span-2">
          <EvidenceChain evidence={evidence} />
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <PocCard pocScript={finding.pocScript} />

          {/* Actions */}
          <Card className="gap-4">
            <CardHeader className="pb-0">
              <CardTitle className="text-sm">Operations</CardTitle>
              <CardDescription className="text-xs">
                Independent re-verification re-runs the detection and appends a{" "}
                <span className="font-mono text-[11px]">reverify</span> record to the WORM ledger.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Button
                variant="outline"
                className="w-full gap-2 border-primary/40 text-primary hover:bg-primary/10 hover:text-primary"
                onClick={() => verifyMutation.mutate()}
                disabled={verifyMutation.isPending}
              >
                {verifyMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                ) : (
                  <RefreshCcw className="h-4 w-4" aria-hidden />
                )}
                {verifyMutation.isPending ? "Re-verifying…" : "Re-verify finding"}
              </Button>
              <Button
                variant="secondary"
                className="w-full gap-2"
                onClick={() => {
                  downloadJson(`swarmscan-finding-${finding.id}.json`, finding);
                  toast({ title: "Finding exported", description: "finding JSON downloaded" });
                }}
              >
                <Download className="h-4 w-4" aria-hidden />
                Export finding JSON
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
