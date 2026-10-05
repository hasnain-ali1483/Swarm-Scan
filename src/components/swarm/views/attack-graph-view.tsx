"use client";

// ─── Attack Graph view: correlated exploitation chains ────────────────────────
// GET /api/attack-graph → chains. Left: SVG graph of the selected chain.
// Right: chain selector + stepwise verification panel with approval gates.

import { useMemo, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Network } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  api,
  type AttackGraphResponse,
} from "@/lib/swarm/types";
import { cn, formatNumber } from "@/lib/swarm/format";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/swarm/findings/states";
import { ChainGraph } from "@/components/swarm/attack-graph/chain-graph";
import { ChainList } from "@/components/swarm/attack-graph/chain-list";
import { StepsPanel } from "@/components/swarm/attack-graph/steps-panel";

export function AttackGraphView() {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["attack-graph"],
    queryFn: () => api<AttackGraphResponse>("/api/attack-graph"),
    placeholderData: keepPreviousData,
  });

  const chains = useMemo(() => data?.chains ?? [], [data]);

  const [scanFilter, setScanFilter] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const scanIds = useMemo(() => Array.from(new Set(chains.map((c) => c.scanId))), [chains]);

  const filtered = useMemo(
    () => (scanFilter === "all" ? chains : chains.filter((c) => c.scanId === scanFilter)),
    [chains, scanFilter]
  );

  // Effective selection falls back to the first chain of the filtered set
  // (derived during render — no effect needed when the filter changes).
  const selected = filtered.find((c) => c.id === selectedId) ?? filtered[0] ?? null;

  const verifiedCount = chains.filter((c) => c.verified).length;

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px] space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Correlated Attack Chains</h2>
          <p className="text-xs text-muted-foreground">
            Multi-step exploitation paths assembled from individual findings by the correlator agent
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="bg-card/60 font-mono text-[11px] text-zinc-400">
            {formatNumber(chains.length)} chains
          </Badge>
          <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 font-mono text-[11px] text-emerald-400">
            {verifiedCount} verified
          </Badge>
        </div>
      </div>

      {/* Scan filter chips (only when chains span multiple scans) */}
      {scanIds.length > 1 ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Scan</span>
          <button
            type="button"
            aria-pressed={scanFilter === "all"}
            onClick={() => setScanFilter("all")}
            className={cn(
              "rounded-full border px-2.5 py-1 font-mono text-[11px] transition-colors",
              scanFilter === "all"
                ? "border-primary/50 bg-primary/10 text-primary"
                : "border-zinc-700/60 bg-zinc-900/40 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
            )}
          >
            All scans
          </button>
          {scanIds.map((id) => (
            <button
              key={id}
              type="button"
              aria-pressed={scanFilter === id}
              onClick={() => setScanFilter(id)}
              title={id}
              className={cn(
                "rounded-full border px-2.5 py-1 font-mono text-[11px] transition-colors",
                scanFilter === id
                  ? "border-primary/50 bg-primary/10 text-primary"
                  : "border-zinc-700/60 bg-zinc-900/40 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
              )}
            >
              {id.slice(0, 8)}
            </button>
          ))}
        </div>
      ) : null}

      {isLoading ? (
        <ListSkeleton rows={5} />
      ) : isError ? (
        <ErrorState
          title="Failed to load attack graph"
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      ) : chains.length === 0 ? (
        <EmptyState
          icon={<Network className="h-5 w-5" aria-hidden />}
          title="No correlated chains"
          description="CorrelatorAgent emits chains when findings compose into exploitation paths."
        />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Network className="h-5 w-5" aria-hidden />}
          title="No chains for this scan"
          description="Switch to another scan or clear the filter to see all correlated chains."
        />
      ) : (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
          className={cn("grid items-start gap-4 lg:grid-cols-3", isFetching && "opacity-70 transition-opacity")}
        >
          {/* Graph (2/3) */}
          <div className="min-w-0 lg:col-span-2">
            {selected ? <ChainGraph key={selected.id} chain={selected} /> : null}
          </div>

          {/* Chain selector + steps (1/3) */}
          <div className="flex flex-col gap-4">
            <Card className="gap-3">
              <CardHeader className="pb-0">
                <CardTitle className="text-sm">Chains</CardTitle>
                <CardDescription className="text-xs">
                  {filtered.length} in the current {scanFilter === "all" ? "view" : "scan"}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ChainList
                  chains={filtered}
                  selectedId={selected?.id ?? null}
                  onSelect={(id) => setSelectedId(id)}
                />
              </CardContent>
            </Card>

            {selected ? <StepsPanel chain={selected} /> : null}
          </div>
        </motion.div>
      )}
    </div>
  );
}
