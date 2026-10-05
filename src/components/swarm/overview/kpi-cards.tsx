"use client";

// ─── KPI cards (Overview row 1) ──────────────────────────────────────────────

import { motion } from "framer-motion";
import {
  Activity,
  BadgeCheck,
  Check,
  Layers,
  Radar,
  Siren,
  TriangleAlert,
  Zap,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/swarm/format";
import type { EngineStats, OverviewResponse } from "@/lib/swarm/types";
import { AnimatedNumber } from "./animated-number";

function KpiCard({
  icon: Icon,
  label,
  value,
  format,
  sub,
  index,
}: {
  icon: LucideIcon;
  label: string;
  value: number | null;
  format?: (n: number) => string;
  sub: ReactNode;
  index: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.05, ease: "easeOut" }}
      className="h-full"
    >
      <Card className="h-full gap-2.5 rounded-xl px-4 py-4">
        <div className="flex items-center justify-between gap-2">
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-primary/25 bg-primary/10">
            <Icon className="h-3.5 w-3.5 text-primary" aria-hidden />
          </span>
          <span className="truncate text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </span>
        </div>
        <div className="font-mono text-2xl font-semibold leading-none tracking-tight">
          {value === null ? (
            <span className="text-zinc-600">—</span>
          ) : (
            <AnimatedNumber value={value} format={format} />
          )}
        </div>
        <div className="min-h-[16px]">{sub}</div>
      </Card>
    </motion.div>
  );
}

export function KpiCards({
  kpis,
  stats,
}: {
  kpis: OverviewResponse["kpis"];
  stats: EngineStats | null;
}) {
  const activeScans = stats?.activeScans ?? kpis.activeScans;
  const reqPerMin = stats?.requestsPerMin ?? kpis.requestsPerMin;
  const hasFp = kpis.fpRate !== null;
  const fpOk = hasFp && (kpis.fpRate as number) < 2;
  const killOk = kpis.killLatencyMs > 0 && kpis.killLatencyMs < 500;

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-6">
      <KpiCard
        index={0}
        icon={Radar}
        label="Active Scans"
        value={activeScans}
        sub={
          <span className="text-[11px] text-muted-foreground">on execution plane</span>
        }
      />
      <KpiCard
        index={1}
        icon={Layers}
        label="Total Scans"
        value={kpis.totalScans}
        sub={<span className="text-[11px] text-muted-foreground">plans dispatched</span>}
      />
      <KpiCard
        index={2}
        icon={Siren}
        label="Findings"
        value={kpis.totalFindings}
        sub={<span className="text-[11px] text-muted-foreground">across all scans</span>}
      />
      <KpiCard
        index={3}
        icon={BadgeCheck}
        label="Confirmed"
        value={kpis.confirmedFindings}
        sub={
          !hasFp ? (
            <span className="text-[11px] text-muted-foreground">FP rate — run benchmark</span>
          ) : (
            <span
              className={cn(
                "flex items-center gap-1 text-[11px]",
                fpOk ? "text-emerald-400" : "text-amber-400"
              )}
            >
              {fpOk ? (
                <Check className="h-3 w-3 shrink-0" aria-hidden />
              ) : (
                <TriangleAlert className="h-3 w-3 shrink-0" aria-hidden />
              )}
              FP rate {kpis.fpRate}% — SLO &lt;2%
            </span>
          )
        }
      />
      <KpiCard
        index={4}
        icon={Activity}
        label="Requests / min"
        value={reqPerMin}
        sub={<span className="text-[11px] text-muted-foreground">live throughput</span>}
      />
      <KpiCard
        index={5}
        icon={Zap}
        label="Kill Latency"
        value={kpis.killLatencyMs > 0 ? kpis.killLatencyMs : null}
        format={(n) => `${Math.round(n)} ms`}
        sub={
          kpis.killLatencyMs > 0 ? (
            <span
              className={cn(
                "flex items-center gap-1 text-[11px]",
                killOk ? "text-emerald-400" : "text-amber-400"
              )}
            >
              {killOk ? (
                <Check className="h-3 w-3 shrink-0" aria-hidden />
              ) : (
                <TriangleAlert className="h-3 w-3 shrink-0" aria-hidden />
              )}
              SLO &lt;500ms — {killOk ? "met" : "breached"}
            </span>
          ) : (
            <span className="text-[11px] text-muted-foreground">SLO &lt;500ms · no kill yet</span>
          )
        }
      />
    </div>
  );
}
