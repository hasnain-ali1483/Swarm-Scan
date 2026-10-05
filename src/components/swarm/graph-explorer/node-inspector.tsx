"use client";

// ─── Node inspector panel (Task 9-a) ─────────────────────────────────────────
// Shows the selected canvas node: kind badge, label, caption, prose detail
// (fetched via GraphQL `node(id:)`), plus cross-view drill-down buttons
// (findings / scans) through the shared UI store.

import { AnimatePresence, motion } from "framer-motion";
import {
  Bot,
  MousePointerClick,
  Network,
  Radar,
  Server,
  Siren,
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
import { Skeleton } from "@/components/ui/skeleton";
import type { GraphNode, GraphNodeKind } from "@/lib/swarm/types";
import { SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { KIND_LABELS } from "./graph-style";

const KIND_ICON: Record<GraphNodeKind, typeof Server> = {
  target: Server,
  scan: Radar,
  agent: Bot,
  finding: Siren,
  chain: Network,
};

const KIND_BADGE: Record<GraphNodeKind, string> = {
  target: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
  scan: "bg-zinc-500/15 text-zinc-300 border-zinc-500/40",
  agent: "bg-teal-500/15 text-teal-300 border-teal-500/40",
  finding: "bg-red-500/15 text-red-400 border-red-500/40",
  chain: "bg-amber-500/15 text-amber-400 border-amber-500/40",
};

function realId(node: GraphNode): string {
  return node.id.slice(2);
}

export interface NodeInspectorProps {
  node: GraphNode | null;
  detail: string | null;
  detailLoading: boolean;
  detailError: string | null;
}

export function NodeInspector({ node, detail, detailLoading, detailError }: NodeInspectorProps) {
  const { openFinding, openScan, setView } = useSwarmUi();
  const Icon = node ? KIND_ICON[node.kind] : MousePointerClick;

  return (
    <Card className="rounded-xl">
      <CardHeader className="px-4 pb-3 sm:px-5">
        <CardTitle className="flex items-center gap-2.5 text-sm">
          <Icon className="h-4 w-4 text-primary" aria-hidden />
          Inspector
        </CardTitle>
        <CardDescription className="text-xs">
          Click any node on the canvas to drill into it
        </CardDescription>
      </CardHeader>
      <CardContent className="px-4 pb-4 sm:px-5">
        <AnimatePresence mode="wait">
          {node === null ? (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="flex flex-col items-center justify-center gap-2.5 rounded-lg border border-dashed bg-card/30 px-4 py-8 text-center"
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-full border border-zinc-700/60 bg-zinc-900/60 text-zinc-400">
                <MousePointerClick className="h-4 w-4" aria-hidden />
              </div>
              <p className="text-sm font-medium text-zinc-300">Select a node</p>
              <p className="max-w-[240px] text-xs text-muted-foreground">
                Hover to trace its edges, click to inspect it here
              </p>
            </motion.div>
          ) : (
            <motion.div
              key={node.id}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.18 }}
              className="space-y-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={cn("text-[10px]", KIND_BADGE[node.kind])}>
                  <Icon className="mr-1 h-3 w-3" aria-hidden />
                  {KIND_LABELS[node.kind]}
                </Badge>
                {node.status && (
                  <Badge variant="outline" className="text-[10px] text-zinc-400">
                    {node.status}
                  </Badge>
                )}
                {node.severity && (
                  <Badge
                    variant="outline"
                    className={cn("text-[10px]", SEVERITY_STYLES[node.severity].badge)}
                  >
                    {node.severity}
                  </Badge>
                )}
                {node.band && (
                  <Badge variant="outline" className="text-[10px] text-zinc-300">
                    {node.band}
                  </Badge>
                )}
              </div>

              <div>
                <p className="text-sm font-medium leading-snug break-words text-zinc-100">
                  {node.label}
                </p>
                <p className="swarm-mono mt-1 text-[11px] text-zinc-500 break-words">
                  {node.sub}
                </p>
              </div>

              <div className="rounded-md border border-border bg-zinc-950/50 p-3">
                {detailLoading ? (
                  <div className="space-y-1.5" aria-busy>
                    <Skeleton className="h-3 w-full rounded" />
                    <Skeleton className="h-3 w-11/12 rounded" />
                    <Skeleton className="h-3 w-4/5 rounded" />
                    <Skeleton className="h-3 w-2/3 rounded" />
                  </div>
                ) : detailError ? (
                  <p role="alert" className="text-xs text-red-400">
                    {detailError}
                  </p>
                ) : (
                  <p className="text-[11.5px] leading-relaxed whitespace-pre-line text-zinc-400">
                    {detail ?? "No detail available for this node."}
                  </p>
                )}
              </div>

              {node.kind === "finding" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full gap-1.5"
                  onClick={() => {
                    setView("findings");
                    openFinding(realId(node));
                  }}
                >
                  <Siren className="h-3.5 w-3.5" aria-hidden />
                  Open in Findings
                </Button>
              )}
              {node.kind === "scan" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full gap-1.5"
                  onClick={() => openScan(realId(node))}
                >
                  <Radar className="h-3.5 w-3.5" aria-hidden />
                  Open in Scans
                </Button>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </CardContent>
    </Card>
  );
}
