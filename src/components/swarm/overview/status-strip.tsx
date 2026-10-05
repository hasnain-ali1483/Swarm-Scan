"use client";

// ─── Execution plane status strip (Overview row 1) ───────────────────────────

import { Activity, Bot, Boxes, Radio, Server, Timer, WifiOff } from "lucide-react";
import { Card } from "@/components/ui/card";
import { useEngineSocket } from "@/components/swarm/providers";
import { cn, formatNumber } from "@/lib/swarm/format";
import type { OverviewResponse } from "@/lib/swarm/types";

export function formatUptime(sec: number): string {
  if (!Number.isFinite(sec) || sec <= 0) return "—";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function StatusStrip({
  engine,
  fallbackReqPerMin,
}: {
  engine: OverviewResponse["engine"];
  fallbackReqPerMin: number;
}) {
  const { connected, stats } = useEngineSocket();

  const tools = engine?.tools ?? [];
  const availableTools = tools.filter((t) => t.available).map((t) => t.name);
  const nucleiOn = availableTools.includes("nuclei");

  const items: {
    label: string;
    value: string;
    icon: typeof Radio;
    iconClass: string;
    valueClass: string;
    pulse?: boolean;
  }[] = [
    {
      label: "Event bus",
      value: connected ? "connected" : "offline",
      icon: connected ? Radio : WifiOff,
      iconClass: connected ? "text-primary" : "text-red-500",
      valueClass: connected ? "text-primary" : "text-red-400",
      pulse: connected,
    },
    {
      label: "Engine",
      value: engine?.healthy ? "healthy" : "degraded",
      icon: Server,
      iconClass: engine?.healthy ? "text-primary" : "text-amber-400",
      valueClass: engine?.healthy ? "text-emerald-400" : "text-amber-400",
    },
    {
      label: "Workers",
      value: `${stats?.workers ?? engine?.workers ?? 0}`,
      icon: Bot,
      iconClass: "text-zinc-400",
      valueClass: "text-zinc-200",
    },
    {
      label: "Uptime",
      value: formatUptime(stats?.uptimeSec ?? engine?.uptimeSec ?? 0),
      icon: Timer,
      iconClass: "text-zinc-400",
      valueClass: "font-mono text-zinc-200",
    },
    {
      label: "Throughput",
      value: `${formatNumber(stats?.requestsPerMin ?? fallbackReqPerMin)} req/min`,
      icon: Activity,
      iconClass: "text-zinc-400",
      valueClass: "font-mono text-zinc-200",
    },
    {
      label: "Scanners",
      value: availableTools.length > 0 ? `${availableTools.length} tool${availableTools.length === 1 ? "" : "s"}${nucleiOn ? " · nuclei" : ""}` : "built-in only",
      icon: Boxes,
      iconClass: nucleiOn ? "text-primary" : "text-zinc-400",
      valueClass: nucleiOn ? "text-emerald-400" : "text-zinc-200",
    },
  ];

  return (
    <Card
      role="status"
      aria-label="Execution plane status"
      className="gap-3 rounded-xl px-4 py-3"
    >
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Execution plane
        </span>
        <span className="font-mono text-[10px] text-zinc-600">
          scan-engine :3003
        </span>
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.label} className="flex min-w-0 items-center gap-2.5">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border bg-muted/40">
                <Icon
                  className={cn("h-3.5 w-3.5", item.iconClass, item.pulse && "swarm-pulse")}
                  aria-hidden
                />
              </span>
              <div className="min-w-0 leading-tight">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  {item.label}
                </div>
                <div className={cn("truncate text-sm font-medium", item.valueClass)}>
                  {item.value}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
