"use client";

// ─── OverviewView — live SOC dashboard (landing experience) ──────────────────
// Row 1: execution plane strip + animated KPI cards
// Row 2: severity bars · confidence bands donut · agent activity
// Row 2.5: capacity learning — per-target polite-rate trends (spec §5.2)
// Row 3: live event bus feed · recent findings
// Row 4: SLO compliance table
// Row 5: continuous monitoring — executive risk trendline (Task 13-b)

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { RotateCw, TriangleAlert } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useEngineSocket } from "@/components/swarm/providers";
import { useToast } from "@/hooks/use-toast";
import { api, type EventLogItem, type OverviewResponse } from "@/lib/swarm/types";
import { useEngineSub } from "@/components/swarm/overview/use-engine-sub";
import { toEventItem } from "@/components/swarm/overview/event-feed";
import { StatusStrip } from "@/components/swarm/overview/status-strip";
import { KpiCards } from "@/components/swarm/overview/kpi-cards";
import { SeverityChart } from "@/components/swarm/overview/severity-chart";
import { BandsDonut } from "@/components/swarm/overview/bands-donut";
import { AgentActivity } from "@/components/swarm/overview/agent-activity";
import { LiveEventFeed } from "@/components/swarm/overview/event-feed";
import { RecentFindings } from "@/components/swarm/overview/recent-findings";
import { SloTable } from "@/components/swarm/overview/slo-table";
const EVENT_BUFFER = 80;

function OverviewSkeleton() {
  return (
    <div className="px-4 py-6 mx-auto w-full max-w-[1600px] lg:px-6">
      <div className="space-y-6" aria-busy="true" aria-label="Loading overview">
        <div className="space-y-4">
          <Skeleton className="h-[92px] w-full rounded-xl" />
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-6">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-[120px] rounded-xl" />
            ))}
          </div>
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-[300px] rounded-xl" />
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-5">
          <Skeleton className="h-[500px] rounded-xl lg:col-span-2" />
          <Skeleton className="h-[500px] rounded-xl lg:col-span-3" />
        </div>
        <Skeleton className="h-[280px] rounded-xl" />
      </div>
    </div>
  );
}

export function OverviewView() {
  const queryClient = useQueryClient();
  const { connected, stats } = useEngineSocket();
  const { toast } = useToast();
  const [liveEvents, setLiveEvents] = useState<EventLogItem[]>([]);

  const query = useQuery({
    queryKey: ["overview"],
    queryFn: () => api<OverviewResponse>("/api/overview"),
    refetchInterval: 10_000,
  });

  // Live event bus → prepend into the local buffer (cap 80).
  useEngineSub("event:new", (e) => {
    setLiveEvents((prev) => [toEventItem(e), ...prev].slice(0, EVENT_BUFFER));
  });

  // New finding → toast + refresh KPIs/feeds.
  useEngineSub("finding:new", ({ finding }) => {
    toast({
      title: "New finding",
      description: `[${finding.severity}] ${finding.title} — confidence ${finding.confidence}`,
    });
    void queryClient.invalidateQueries({ queryKey: ["overview"] });
  });

  // Feed = live socket events on top of the fetched seed (newest first, cap 80,
  // deduped by type+message+ts so refetches do not double-list live events).
  const feedEvents = useMemo(() => {
    const seen = new Set<string>();
    const merged: EventLogItem[] = [];
    for (const e of [...liveEvents, ...(query.data?.recentEvents ?? [])]) {
      const key = `${e.type}|${e.message}|${e.createdAt}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(e);
      if (merged.length >= EVENT_BUFFER) break;
    }
    return merged;
  }, [liveEvents, query.data?.recentEvents]);

  if (query.isError) {
    return (
      <div className="px-4 py-6 mx-auto w-full max-w-[1600px] lg:px-6">
        <Alert variant="destructive" role="alert">
          <TriangleAlert className="h-4 w-4" aria-hidden />
          <AlertTitle>Control plane unreachable</AlertTitle>
          <AlertDescription className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-xs">
              {query.error instanceof Error
                ? query.error.message
                : "Failed to load overview data"}
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

  if (query.isPending) {
    return <OverviewSkeleton />;
  }

  const data = query.data;

  return (
    <div className="px-4 py-6 mx-auto w-full max-w-[1600px] lg:px-6">
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: "easeOut" }}
        className="space-y-6"
      >
        {/* Row 1 — system status + KPIs */}
        <section aria-label="System status" className="space-y-4">
          <StatusStrip
            engine={data.engine}
            fallbackReqPerMin={data.kpis.requestsPerMin}
          />
          <KpiCards kpis={data.kpis} stats={stats} />
        </section>

        {/* Row 2 — analytics */}
        <section aria-label="Analytics" className="grid items-stretch gap-4 lg:grid-cols-3">
          <SeverityChart severity={data.severity} />
          <BandsDonut bands={data.bands} />
          <AgentActivity agents={data.agentActivity} />
        </section>

        {/* Row 3 — live feed + recent findings */}
        <section aria-label="Live activity" className="grid items-stretch gap-4 lg:grid-cols-5">
          <div className="lg:col-span-2">
            <LiveEventFeed connected={connected} events={feedEvents} />
          </div>
          <div className="lg:col-span-3">
            <RecentFindings findings={data.recentFindings} />
          </div>
        </section>

        {/* Row 4 — SLO table */}
        <section aria-label="Service level objectives">
          <SloTable kpis={data.kpis} />
        </section>
      </motion.div>
    </div>
  );
}
