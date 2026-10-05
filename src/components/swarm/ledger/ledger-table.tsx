"use client";

// ─── WORM ledger table: sticky header, hash chain columns, mobile cards ──────

import { motion } from "framer-motion";
import { Link2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn, formatHash, timeAgo, truncateMiddle } from "@/lib/swarm/format";
import type { LedgerResponse } from "@/lib/swarm/types";
import { CopyButton } from "@/components/swarm/findings/copy-button";
import { evidenceKindMeta } from "@/components/swarm/findings/evidence-kinds";

export type LedgerEntry = LedgerResponse["entries"][number];

function KindBadge({ kind }: { kind: string }) {
  const meta = evidenceKindMeta(kind);
  return (
    <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", meta.badge)}>
      {meta.label}
    </Badge>
  );
}

function TimeCell({ iso }: { iso: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="cursor-default text-[11px] text-zinc-400" tabIndex={0}>
          {timeAgo(iso)}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">
        <span className="font-mono text-[11px]">{new Date(iso).toLocaleString()}</span>
      </TooltipContent>
    </Tooltip>
  );
}

function LedgerRow({ entry }: { entry: LedgerEntry }) {
  return (
    <TableRow className="group/row border-border/70 hover:bg-zinc-800/40">
      <TableCell className="font-mono text-[11px] text-zinc-400">{entry.sequence}</TableCell>
      <TableCell>
        <TimeCell iso={entry.createdAt} />
      </TableCell>
      <TableCell className="max-w-[170px]">
        <span className="block truncate font-mono text-[11px] text-zinc-400" title={entry.scanTarget}>
          {truncateMiddle(entry.scanTarget, 24)}
        </span>
      </TableCell>
      <TableCell>
        <KindBadge kind={entry.kind} />
      </TableCell>
      <TableCell className="max-w-[190px]">
        {entry.findingTitle ? (
          <span className="block truncate text-xs text-zinc-400" title={entry.findingTitle}>
            {entry.findingTitle}
          </span>
        ) : (
          <span className="text-zinc-600">—</span>
        )}
      </TableCell>
      <TableCell className="font-mono text-[11px] tabular-nums text-zinc-300">
        {entry.lr.toFixed(1)}
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-1">
          <span className="font-mono text-[11px] text-zinc-400" title={entry.hash}>
            {formatHash(entry.hash, 10, 6)}
          </span>
          <CopyButton value={entry.hash} toastLabel="Hash" className="opacity-0 transition-opacity group-hover/row:opacity-100 focus-visible:opacity-100" />
        </span>
      </TableCell>
      <TableCell>
        <span className="font-mono text-[11px] text-zinc-500" title={entry.prevHash}>
          {entry.prevHash ? formatHash(entry.prevHash, 10, 6) : "—"}
        </span>
      </TableCell>
      <TableCell>
        <Link2 className="h-3.5 w-3.5 text-zinc-500" aria-hidden />
      </TableCell>
    </TableRow>
  );
}

export function LedgerTable({ entries }: { entries: LedgerEntry[] }) {
  return (
    <>
      {/* Desktop table */}
      <div className="hidden overflow-hidden rounded-lg border md:block">
        <div className="swarm-scroll max-h-[560px] overflow-auto">
          <Table className="min-w-[960px]">
            <TableHeader className="sticky top-0 z-10 bg-zinc-950/95 backdrop-blur-sm">
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-12 text-[10px] uppercase tracking-wider text-zinc-500">Seq</TableHead>
                <TableHead className="w-20 text-[10px] uppercase tracking-wider text-zinc-500">Time</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider text-zinc-500">Scan target</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider text-zinc-500">Kind</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider text-zinc-500">Finding</TableHead>
                <TableHead className="w-14 text-[10px] uppercase tracking-wider text-zinc-500">LR</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider text-zinc-500">Hash</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider text-zinc-500">Prev hash</TableHead>
                <TableHead className="w-10" aria-label="Chain link" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {entries.map((entry) => (
                <LedgerRow key={entry.id} entry={entry} />
              ))}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Mobile cards */}
      <div className="swarm-scroll max-h-[520px] space-y-2 overflow-y-auto md:hidden">
        {entries.map((entry, i) => (
          <motion.div
            key={entry.id}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2, delay: Math.min(i * 0.02, 0.3) }}
            className="group/row rounded-lg border border-border bg-card/40 p-3"
          >
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-zinc-500">#{entry.sequence}</span>
              <KindBadge kind={entry.kind} />
              <span className="ml-auto text-[11px] text-zinc-500" title={new Date(entry.createdAt).toISOString()}>
                {timeAgo(entry.createdAt)}
              </span>
            </div>
            <p className="mt-1.5 truncate font-mono text-[11px] text-zinc-400" title={entry.scanTarget}>
              {truncateMiddle(entry.scanTarget, 32)}
            </p>
            {entry.findingTitle ? (
              <p className="mt-0.5 truncate text-xs text-zinc-400" title={entry.findingTitle}>
                {entry.findingTitle}
              </p>
            ) : null}
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-zinc-500">
              <span className="flex items-center gap-1">
                LR <span className="text-zinc-300">{entry.lr.toFixed(1)}</span>
              </span>
              <span className="flex items-center gap-1">
                <span title={entry.hash}>{formatHash(entry.hash, 8, 5)}</span>
                <CopyButton value={entry.hash} toastLabel="Hash" />
              </span>
              <Link2 className="h-3 w-3 text-zinc-600" aria-hidden />
            </div>
          </motion.div>
        ))}
      </div>
    </>
  );
}
