"use client";

// ─── Graph Explorer view (13th view, Task 9-a · live mode: Task 12-a) ────────
// The GraphQL Output Plane: a live query console (POST /api/graphql) whose
// `graph(...)` results drive a force-directed SVG canvas of the finding graph
// (targets → scans → agents → findings → attack chains), with an inspector
// drill-down (node(id:)) and legend/stats. Layout: canvas (2/3) left, live
// feed + console + inspector + legend right; stacks vertically on mobile.
//
// LIVE MODE (Task 12-a): the view subscribes to the engine socket bus via
// useLiveGraph(useEngineSub("finding:new")) — the feed strip shows streamed
// findings, related nodes pulse on the canvas, and off-graph findings (their
// f:{id} node isn't in the current query result — e.g. a scan still running)
// surface as a "+N new findings — re-run" chip that refreshes the graph.

import { useCallback, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { AlertCircle, GitBranch, Loader2, Radio, RotateCw, Waypoints } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api, type FindingsListResponse, type GqlResponse, type GraphData, type GraphNode } from "@/lib/swarm/types";
import { cn } from "@/lib/swarm/format";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { useEngineSocket } from "@/components/swarm/providers";
import { useGraphConsole } from "@/components/swarm/graph-explorer/use-graph-console";
import { DEFAULT_QUERY, NODE_QUERY } from "@/components/swarm/graph-explorer/presets";
import { GraphCanvas } from "@/components/swarm/graph-explorer/graph-canvas";
import { QueryConsole } from "@/components/swarm/graph-explorer/query-console";
import { NodeInspector } from "@/components/swarm/graph-explorer/node-inspector";
import { GraphLegend } from "@/components/swarm/graph-explorer/graph-legend";
import { LiveFeed } from "@/components/swarm/graph-explorer/live-feed";
import {
  useLiveGraph,
  type LiveFindingEvent,
} from "@/components/swarm/graph-explorer/use-live-graph";

function HeaderPill({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="flex items-baseline gap-1.5 rounded-md border border-border bg-zinc-950/60 px-2.5 py-1">
      <span className="swarm-mono text-xs font-semibold tabular-nums text-primary">
        {value ?? "—"}
      </span>
      <span className="text-[10px] text-zinc-500">{label}</span>
    </div>
  );
}

/** LIVE bus chip — emerald + pulsing dot when the socket bus is connected and
 *  streaming is not paused; zinc when paused; dimmed when the bus is down. */
function LiveBusChip({
  connected,
  isPaused,
  totalSeen,
}: {
  connected: boolean;
  isPaused: boolean;
  totalSeen: number;
}) {
  const live = connected && !isPaused;
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-md border px-2.5 py-1",
        isPaused
          ? "border-zinc-700 bg-zinc-900/60"
          : connected
            ? "border-emerald-500/40 bg-emerald-500/10"
            : "border-zinc-700/60 bg-zinc-900/40",
      )}
      title={
        connected
          ? "finding:new events stream from the engine socket bus into the graph"
          : "engine socket bus disconnected — reconnecting…"
      }
    >
      {live ? (
        <span
          className="swarm-pulse h-1.5 w-1.5 rounded-full bg-emerald-400 text-emerald-400"
          aria-hidden
        />
      ) : (
        <Radio
          className={cn("h-3 w-3", isPaused ? "text-zinc-500" : "text-zinc-600")}
          aria-hidden
        />
      )}
      <span
        className={cn(
          "text-[10px] font-medium",
          isPaused ? "text-zinc-400" : connected ? "text-emerald-400" : "text-zinc-500",
        )}
      >
        {isPaused
          ? "paused"
          : connected
            ? `bus live · ${totalSeen} findings streamed`
            : "bus offline"}
      </span>
    </div>
  );
}

export function GraphExplorerView() {
  const { query, setQuery, result, running, run, applyPreset, graphData, graphSeq } =
    useGraphConsole();

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedNode = useMemo(
    () => graphData?.nodes.find((n) => n.id === selectedId) ?? null,
    [graphData, selectedId],
  );

  // ── Live mode (Task 12-a): the engine socket bus drives the feed + pulses ──
  const { connected } = useEngineSocket();
  const live = useLiveGraph(graphData);
  const { setView, openFinding } = useSwarmUi();

  // Feed row click: select + pulse the finding node when the current graph
  // carries it. Otherwise deep-link into the Findings view — the engine's
  // finding id is engine-local (the control plane re-ids findings at ingest),
  // so resolve the ingested DB row (same scan + agent + title) to open a real
  // detail; a scan still running has nothing ingested yet → findings list.
  const handleRowClick = useCallback(
    async (ev: LiveFindingEvent) => {
      const nodeId = `f:${ev.findingId}`;
      if (graphData?.nodes.some((n) => n.id === nodeId)) {
        setSelectedId(nodeId);
        live.pulseNode(nodeId);
        return;
      }
      try {
        const res = await api<FindingsListResponse>(
          `/api/findings?scanId=${encodeURIComponent(ev.scanId)}&agentKey=${encodeURIComponent(ev.agentKey)}&pageSize=50`,
        );
        const match = res.findings.find((f) => f.title === ev.title);
        setView("findings");
        if (match) openFinding(match.id);
      } catch {
        setView("findings");
      }
    },
    [graphData, live, setView, openFinding],
  );

  // Inspector drill-down: fetch the prose detail via GraphQL node(id:) — cached
  // per node id (5 min staleTime) so revisiting a node is instant.
  const nodeQuery = useQuery({
    queryKey: ["gql-node", selectedNode?.id ?? null],
    enabled: selectedNode !== null,
    staleTime: 5 * 60_000,
    retry: false,
    queryFn: ({ queryKey }) => {
      const id = queryKey[1] as string;
      return api<GqlResponse<{ node: { detail: string } | null }>>("/api/graphql", {
        method: "POST",
        body: JSON.stringify({ query: NODE_QUERY, variables: { id } }),
      });
    },
  });
  const detail = nodeQuery.data?.data?.node?.detail ?? null;
  const detailError = nodeQuery.error
    ? nodeQuery.error instanceof Error
      ? nodeQuery.error.message
      : "node(id:) query failed"
    : (nodeQuery.data?.errors?.[0]?.message ?? null);

  const stats = graphData?.stats ?? null;
  const hadErrors = (result?.errors?.length ?? 0) > 0;

  const canvasBody = (() => {
    if (result === null && running) {
      return (
        <div className="space-y-3" aria-busy>
          <Skeleton className="h-8 w-1/3 rounded" />
          <Skeleton className="h-[280px] w-full rounded-lg" />
          <p className="flex items-center gap-2 text-xs text-zinc-500">
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            Running the default graph query…
          </p>
        </div>
      );
    }
    if (graphData && graphData.nodes.length > 0) {
      return (
        <GraphCanvas
          key={graphSeq}
          data={graphData}
          selectedId={selectedId}
          onSelect={(n: GraphNode) =>
            setSelectedId((cur) => (cur === n.id ? null : n.id))
          }
          pulseIds={live.pulseIds}
        />
      );
    }
    if (result?.transportError) {
      return (
        <div
          role="alert"
          className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-6 py-10 text-center"
        >
          <AlertCircle className="h-6 w-6 text-destructive" aria-hidden />
          <div>
            <p className="text-sm font-medium">GraphQL endpoint unreachable</p>
            <p className="mt-1 max-w-md text-xs break-words text-muted-foreground">
              {result.transportError}
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => run(DEFAULT_QUERY)} disabled={running}>
            <Loader2 className={cn("h-3.5 w-3.5", running && "animate-spin")} aria-hidden />
            Retry graph query
          </Button>
        </div>
      );
    }
    if (graphData && graphData.nodes.length === 0) {
      return (
        <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed bg-card/30 px-6 py-10 text-center">
          <GitBranch className="h-6 w-6 text-zinc-500" aria-hidden />
          <p className="text-sm font-medium text-zinc-300">No nodes matched the current filters</p>
          <p className="max-w-md text-xs text-muted-foreground">
            Loosen the severity/band/agentKey arguments or raise the findings limit.
          </p>
        </div>
      );
    }
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed bg-card/30 px-6 py-10 text-center">
        <GitBranch className="h-6 w-6 text-zinc-500" aria-hidden />
        <p className="text-sm font-medium text-zinc-300">
          {hadErrors ? "The last query errored — see the console pane" : "The last query returned no graph"}
        </p>
        <p className="max-w-md text-xs text-muted-foreground">
          The canvas renders whatever a <code className="font-mono text-[11px] text-primary">graph(...)</code>{" "}
          query returns. Run one to populate it.
        </p>
        <Button variant="outline" size="sm" onClick={() => applyPreset(DEFAULT_QUERY)} disabled={running}>
          Run full graph
        </Button>
      </div>
    );
  })();

  return (
    <div className="mx-auto w-full max-w-[1600px] space-y-4 px-4 py-6 lg:px-6">
      {/* Header strip */}
      <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
        <Card className="rounded-xl">
          <CardContent className="flex flex-col gap-3 px-4 py-4 sm:px-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-primary/30 bg-primary/10">
                <Waypoints className="h-5 w-5 text-primary" aria-hidden />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base font-semibold leading-tight">GraphQL Output Plane</h2>
                  <Badge
                    variant="outline"
                    className="swarm-mono text-[10px] text-primary border-primary/40"
                  >
                    POST /api/graphql
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  The correlator&apos;s attack graph, queryable — REST for the operators, GraphQL
                  for the machines
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5" aria-label="Current graph statistics">
              <LiveBusChip
                connected={connected}
                isPaused={live.isPaused}
                totalSeen={live.totalSeen}
              />
              {live.offGraphCount > 0 && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => run()}
                  disabled={running}
                  className="h-7 gap-1.5 rounded-full border-emerald-500/50 bg-emerald-500/10 px-3 text-[11px] text-emerald-400 hover:bg-emerald-500/15 hover:text-emerald-300"
                  title="Findings streamed on the bus since the last query — re-run to fold them into the graph"
                >
                  <RotateCw className={cn("h-3 w-3", running && "animate-spin")} aria-hidden />
                  +{live.offGraphCount} new findings since last query — re-run
                </Button>
              )}
              <HeaderPill label="nodes" value={stats?.nodes ?? null} />
              <HeaderPill label="edges" value={stats?.edges ?? null} />
              <HeaderPill label="targets" value={stats?.targets ?? null} />
              <HeaderPill label="agents" value={stats?.agents ?? null} />
              <HeaderPill label="findings" value={stats?.findings ?? null} />
              <HeaderPill label="chains" value={stats?.chains ?? null} />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Canvas + console/inspector/legend */}
      <div className="grid gap-4 xl:grid-cols-3">
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.05 }}
          className="min-w-0 xl:col-span-2"
        >
          <Card className="rounded-xl gap-3">
            <CardContent className="px-2 pb-4 pt-4 sm:px-4">{canvasBody}</CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.1 }}
          className="min-w-0 space-y-4"
        >
          {/* live feed strip — finding:new over the socket bus */}
          <LiveFeed
            events={live.events}
            totalSeen={live.totalSeen}
            offGraphCount={live.offGraphCount}
            isPaused={live.isPaused}
            bufferedCount={live.bufferedCount}
            connected={connected}
            onToggle={live.toggle}
            onClear={live.clear}
            onRowClick={handleRowClick}
          />
          <QueryConsole
            query={query}
            setQuery={setQuery}
            result={result}
            running={running}
            onRun={run}
            onPreset={applyPreset}
            liveMode={!live.isPaused}
            graphRendered={
              !hadErrors &&
              !result?.transportError &&
              result?.data !== null &&
              typeof result?.data === "object" &&
              result !== null &&
              "graph" in (result.data ?? {})
            }
          />
          <NodeInspector
            node={selectedNode}
            detail={detail}
            detailLoading={nodeQuery.isFetching}
            detailError={detailError}
          />
          <GraphLegend stats={stats} />
        </motion.div>
      </div>
    </div>
  );
}
