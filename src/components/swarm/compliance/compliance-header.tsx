"use client";

// ─── Compliance header — framework / period / ledger attestation + KPIs ──────

import { motion } from "framer-motion";
import { format as formatDate } from "date-fns";
import {
  CircleDot,
  FileJson,
  Layers,
  ShieldCheck,
  ShieldX,
  TriangleAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/swarm/format";
import type { CompliancePack } from "@/lib/swarm/types";

function KpiCard({
  icon: Icon,
  label,
  value,
  tone,
  delay,
}: {
  icon: typeof ShieldCheck;
  label: string;
  value: string;
  tone: string;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.25 }}
      className="flex h-[62px] items-center gap-3 rounded-lg border bg-card/60 px-3.5"
    >
      <Icon className={cn("h-4.5 w-4.5 shrink-0", tone)} aria-hidden />
      <div className="min-w-0 flex flex-col justify-center gap-0.5">
        <div className={cn("font-mono text-lg leading-none font-semibold tabular-nums", tone)}>
          {value}
        </div>
        <div className="truncate text-[10px] uppercase tracking-wider leading-none text-muted-foreground">
          {label}
        </div>
      </div>
    </motion.div>
  );
}

export function ComplianceHeader({ pack }: { pack: CompliancePack }) {
  const s = pack.summary;
  const chainHead12 = s.chainHead.slice(0, 12);

  const kpis = [
    { icon: ShieldCheck, label: "satisfied", value: String(s.satisfied), tone: "text-emerald-400" },
    { icon: TriangleAlert, label: "partial", value: String(s.partial), tone: "text-amber-400" },
    { icon: CircleDot, label: "gaps", value: String(s.gaps), tone: "text-red-400" },
    { icon: Layers, label: "evidence entries", value: String(s.evidenceEntries), tone: "text-primary" },
    { icon: FileJson, label: "findings covered", value: String(s.findingsCovered), tone: "text-teal-300" },
  ];

  return (
    <div>
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-wrap items-start justify-between gap-3"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldCheck className="h-4.5 w-4.5 text-primary" aria-hidden />
            <h2 className="text-lg font-semibold tracking-tight">Compliance evidence</h2>
            <Badge
              variant="outline"
              className="border-primary/40 bg-primary/10 font-mono text-[10px] uppercase tracking-wider text-primary"
            >
              {pack.framework}
            </Badge>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Point-in-time evidence bundles cut from the hash-chained WORM ledger — control →
            evidence mapping with chain-head attestation. Exports land in the audit trail, never
            as side-channel files.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-md border border-zinc-800 bg-card/60 px-2.5 py-1 font-mono text-[10px] text-zinc-400">
            period {formatDate(new Date(pack.periodStart), "MMM d, yyyy")} –{" "}
            {formatDate(new Date(pack.periodEnd), "MMM d, yyyy")}
          </span>
          <span className="rounded-md border border-zinc-800 bg-card/60 px-2.5 py-1 font-mono text-[10px] text-zinc-400">
            generated {formatDate(new Date(pack.generatedAt), "MMM d, HH:mm")} UTC
          </span>
          {s.ledgerValid ? (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 font-mono text-[10px] text-emerald-300">
              <ShieldCheck className="h-3 w-3" aria-hidden />
              WORM chain intact · head {chainHead12}…
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-md border border-red-500/40 bg-red-500/10 px-2.5 py-1 font-mono text-[10px] text-red-300">
              <ShieldX className="h-3 w-3" aria-hidden />
              WORM chain BROKEN — pack not attestable
            </span>
          )}
        </div>
      </motion.div>

      <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {kpis.map((kpi, i) => (
          <KpiCard
            key={kpi.label}
            icon={kpi.icon}
            label={kpi.label}
            value={kpi.value}
            tone={kpi.tone}
            delay={0.05 * i}
          />
        ))}
      </div>
    </div>
  );
}
