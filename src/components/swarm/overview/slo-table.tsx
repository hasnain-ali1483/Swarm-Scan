"use client";

// ─── SLO compliance table (Overview row 4, spec §6) ──────────────────────────

import { Check, Minus, TriangleAlert } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/swarm/format";
import type { OverviewResponse } from "@/lib/swarm/types";

type SloStatus = "pass" | "warn" | "none";

function SloStatusCell({ status }: { status: SloStatus }) {
  if (status === "pass") {
    return (
      <span className="flex items-center gap-1.5 text-emerald-400">
        <Check className="h-3.5 w-3.5" aria-hidden />
        <span className="text-[11px] font-medium">pass</span>
        <span className="sr-only">objective met</span>
      </span>
    );
  }
  if (status === "warn") {
    return (
      <span className="flex items-center gap-1.5 text-amber-400">
        <TriangleAlert className="h-3.5 w-3.5" aria-hidden />
        <span className="text-[11px] font-medium">warn</span>
        <span className="sr-only">objective at risk</span>
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1.5 text-zinc-500">
      <Minus className="h-3.5 w-3.5" aria-hidden />
      <span className="text-[11px] font-medium">n/a</span>
      <span className="sr-only">no data yet</span>
    </span>
  );
}

export function SloTable({ kpis }: { kpis: OverviewResponse["kpis"] }) {
  const killLatency = kpis.killLatencyMs;
  const fp = kpis.fpRate;
  const det = kpis.detectionRate;
  const rows: { slo: string; target: string; actual: string; status: SloStatus }[] = [
    {
      slo: "Finding false-positive rate",
      target: "< 2%",
      actual: fp === null ? "not measured" : `${fp}%`,
      status: fp === null ? "none" : fp < 2 ? "pass" : "warn",
    },
    {
      slo: "FN benchmark (recall)",
      target: "≥ 90%",
      actual: det === null ? "not measured" : `${det}%`,
      status: det === null ? "none" : det >= 90 ? "pass" : "warn",
    },
    {
      slo: "Kill-switch latency",
      target: "< 500 ms",
      actual: killLatency > 0 ? `${killLatency} ms` : "not engaged",
      status: killLatency > 0 ? (killLatency < 500 ? "pass" : "warn") : "none",
    },
  ];

  return (
    <Card className="gap-3 rounded-xl px-4 py-4 sm:px-5">
      <CardHeader className="px-0">
        <CardTitle className="text-sm">Service Level Objectives</CardTitle>
        <CardDescription className="text-xs">
          Platform quality gates from the SwarmScan specification §6
        </CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        <div className="overflow-x-auto swarm-scroll">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="h-8 text-[11px] uppercase tracking-wider text-muted-foreground">
                  Objective
                </TableHead>
                <TableHead className="h-8 text-[11px] uppercase tracking-wider text-muted-foreground">
                  Target
                </TableHead>
                <TableHead className="h-8 text-[11px] uppercase tracking-wider text-muted-foreground">
                  Actual
                </TableHead>
                <TableHead className="h-8 text-right text-[11px] uppercase tracking-wider text-muted-foreground">
                  Status
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.slo} className="border-border/60">
                  <TableCell className="py-2 text-[13px] font-medium text-zinc-200">
                    {row.slo}
                  </TableCell>
                  <TableCell className="py-2 font-mono text-xs text-zinc-400">
                    {row.target}
                  </TableCell>
                  <TableCell className="py-2 font-mono text-xs text-zinc-400">
                    {row.actual}
                  </TableCell>
                  <TableCell className="py-2 text-right">
                    <SloStatusCell status={row.status} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        <p className={cn("mt-2 text-[11px] text-zinc-600")}>
          Sustained SLO compliance is a hard gate for the aggressive policy tier.
        </p>
      </CardContent>
    </Card>
  );
}
