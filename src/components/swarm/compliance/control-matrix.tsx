"use client";

// ─── Control matrix — SOC 2 TSC cards with evidence-ref drawers ──────────────

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronRight, FileJson, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
} from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/swarm/format";
import type { ComplianceControl, ControlStatus } from "@/lib/swarm/types";

const STATUS_META: Record<
  ControlStatus,
  { badge: string; label: string; bar: string; note: string }
> = {
  satisfied: {
    badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    label: "satisfied",
    bar: "[&_[data-slot=progress-indicator]]:bg-emerald-500",
    note: "border-amber-500/30 bg-amber-500/[0.06] text-amber-300/90",
  },
  partial: {
    badge: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    label: "partial",
    bar: "[&_[data-slot=progress-indicator]]:bg-amber-500",
    note: "border-amber-500/30 bg-amber-500/[0.06] text-amber-300/90",
  },
  gap: {
    badge: "border-red-500/40 bg-red-500/10 text-red-300",
    label: "gap",
    bar: "[&_[data-slot=progress-indicator]]:bg-red-500",
    note: "border-red-500/30 bg-red-500/[0.06] text-red-300/90",
  },
};

function ControlCard({ control, index }: { control: ComplianceControl; index: number }) {
  const [open, setOpen] = useState(false);
  const meta = STATUS_META[control.status];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.05, 0.3), duration: 0.3 }}
    >
      <Card className="flex h-full flex-col border-border/80 bg-card/40">
        <CardHeader className="gap-2 pb-3">
          <div className="flex items-start justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <Badge
                variant="outline"
                className="shrink-0 border-zinc-700 bg-zinc-900/60 font-mono text-[10px] tracking-wider text-zinc-300"
              >
                {control.id}
              </Badge>
              <h3 className="min-w-0 truncate text-sm font-medium" title={control.title}>
                {control.title}
              </h3>
            </div>
            <Badge variant="outline" className={cn("shrink-0 text-[10px] uppercase", meta.badge)}>
              {meta.label}
            </Badge>
          </div>
          <p
            className="line-clamp-3 text-xs leading-relaxed text-zinc-500"
            title={control.description}
          >
            {control.description}
          </p>
        </CardHeader>

        <CardContent className="flex flex-1 flex-col gap-3 pb-4">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-wider text-zinc-500">
              <span className="flex items-center gap-1.5">
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    control.status === "satisfied" && "bg-emerald-500",
                    control.status === "partial" && "bg-amber-500",
                    control.status === "gap" && "bg-red-500"
                  )}
                  aria-hidden
                />
                evidence coverage
              </span>
              <span className="tabular-nums text-zinc-400">
                {control.coveragePct}% · {control.evidenceCount} refs
              </span>
            </div>
            <Progress
              value={control.coveragePct}
              aria-label={`${control.id} evidence coverage ${control.coveragePct}%`}
              className={cn("h-1.5 bg-zinc-800/80", meta.bar)}
            />
          </div>

          {control.gapNote ? (
            <div
              role="note"
              className={cn(
                "flex gap-2 rounded-md border px-2.5 py-2 text-[11px] leading-relaxed",
                meta.note
              )}
            >
              <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
              <span className="min-w-0">
                <span className="font-semibold uppercase tracking-wider">{meta.label}</span>
                <span className="text-zinc-400"> — </span>
                {control.gapNote}
              </span>
            </div>
          ) : null}

          <div className="mt-auto">
            {control.evidence.length > 0 ? (
              <Collapsible open={open} onOpenChange={setOpen}>
                <CollapsibleTrigger asChild>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 gap-1.5 px-2 text-[11px] text-zinc-400 hover:text-zinc-200"
                    aria-expanded={open}
                  >
                    <ChevronRight
                      className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-90")}
                      aria-hidden
                    />
                    Evidence refs · {control.evidenceCount}
                  </Button>
                </CollapsibleTrigger>
                <AnimatePresence initial={false}>
                  {open ? (
                    <CollapsibleContent className="mt-1.5">
                      <div className="max-h-44 space-y-1 overflow-y-auto rounded-md border border-zinc-800 bg-zinc-950/50 p-2 swarm-scroll">
                        {control.evidence.map((ref) => (
                          <div
                            key={ref.entryId}
                            className="flex items-baseline gap-1.5 font-mono text-[10px] leading-relaxed text-zinc-500"
                            title={`entry ${ref.entryId} · ${ref.at} · ${ref.hash}`}
                          >
                            <span className="shrink-0 text-zinc-600">seq</span>
                            <span className="shrink-0 tabular-nums text-zinc-400">
                              {ref.sequence}
                            </span>
                            <span className="shrink-0 text-primary/80">{ref.kind}</span>
                            <span className="shrink-0 text-zinc-600">·</span>
                            <span className="shrink-0 text-zinc-500">
                              {ref.hash.slice(0, 12)}…
                            </span>
                            <span className="shrink-0 text-zinc-600">·</span>
                            <span className="min-w-0 truncate text-zinc-400">
                              {ref.findingTitle ?? "scan-level evidence"}
                            </span>
                          </div>
                        ))}
                        {control.evidenceCount > control.evidence.length ? (
                          <p className="pt-0.5 font-mono text-[10px] text-zinc-600">
                            + {control.evidenceCount - control.evidence.length} more in the
                            export pack
                          </p>
                        ) : null}
                      </div>
                    </CollapsibleContent>
                  ) : null}
                </AnimatePresence>
              </Collapsible>
            ) : (
              <div className="flex items-center gap-1.5 font-mono text-[10px] text-zinc-600">
                <FileJson className="h-3 w-3" aria-hidden />
                0 ledger refs mapped
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

export function ControlMatrix({ controls }: { controls: ComplianceControl[] }) {
  return (
    <section aria-label="SOC 2 control matrix" className="min-w-0">
      <div className="mb-2.5 flex items-center justify-between">
        <h3 className="text-sm font-medium">Control matrix</h3>
        <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
          {controls.length} SOC 2 TSC controls · Trust Services Criteria
        </span>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {controls.map((control, i) => (
          <ControlCard key={control.id} control={control} index={i} />
        ))}
      </div>
    </section>
  );
}
