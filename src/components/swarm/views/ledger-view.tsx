"use client";

// ─── Evidence Ledger view: WORM hash-chain audit trail ────────────────────────
// GET /api/ledger?limit=200 → entries; integrity verification banner; scan
// filter; export; compliance stats strip.

import { useMemo, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Download, ScrollText } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { api, type LedgerResponse } from "@/lib/swarm/types";
import { cn, formatHash, formatNumber, truncateMiddle } from "@/lib/swarm/format";
import { CopyButton } from "@/components/swarm/findings/copy-button";
import { downloadJson } from "@/components/swarm/findings/browser-utils";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/swarm/findings/states";
import { LedgerTable } from "@/components/swarm/ledger/ledger-table";
import { VerifyBanner } from "@/components/swarm/ledger/verify-banner";

export function LedgerView() {
  const { toast } = useToast();
  const [scanFilter, setScanFilter] = useState<string>("all");

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["ledger"],
    queryFn: () => api<LedgerResponse>("/api/ledger?limit=200"),
    placeholderData: keepPreviousData,
  });

  // Sort ascending by sequence → chain order (prevHash points at the row above).
  const entries = useMemo(() => {
    const list = data?.entries ?? [];
    return [...list].sort((a, b) => a.sequence - b.sequence);
  }, [data]);

  const scanTargets = useMemo(() => {
    const set = new Set(entries.map((e) => e.scanTarget));
    return Array.from(set).sort();
  }, [entries]);

  const filtered = useMemo(
    () => (scanFilter === "all" ? entries : entries.filter((e) => e.scanTarget === scanFilter)),
    [entries, scanFilter]
  );

  // Head = the highest-sequence entry currently loaded.
  const head = useMemo(
    () => entries.reduce<LedgerResponse["entries"][number] | null>((acc, e) => (!acc || e.sequence > acc.sequence ? e : acc), null),
    [entries]
  );

  const distinctFindings = useMemo(() => new Set(filtered.filter((e) => e.findingId).map((e) => e.findingId)).size, [filtered]);
  const distinctScans = useMemo(() => new Set(filtered.map((e) => e.scanId)).size, [filtered]);

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px] space-y-4">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h2 className="flex flex-wrap items-center gap-2.5 text-lg font-semibold tracking-tight">
            WORM Evidence Ledger
            <Badge variant="outline" className="border-zinc-700/70 bg-zinc-900/50 font-mono text-[11px] text-zinc-400">
              {formatNumber(data?.total ?? 0)} entries
            </Badge>
          </h2>
          {head ? (
            <p className="mt-1.5 flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-zinc-500">
              <span aria-hidden>head</span>
              <span className="text-zinc-300" title={head.hash}>
                {formatHash(head.hash, 14, 10)}
              </span>
              <CopyButton value={head.hash} toastLabel="Head hash" />
              <span className="text-zinc-600" aria-hidden>· seq #{head.sequence}</span>
            </p>
          ) : null}
        </div>
        <Button
          variant="outline"
          size="sm"
          className="gap-2"
          onClick={() => {
            downloadJson("swarmscan-ledger-export.json", {
              exportedAt: new Date().toISOString(),
              total: data?.total ?? filtered.length,
              scanFilter,
              entries: filtered,
            });
            toast({ title: "Ledger exported", description: `${filtered.length} entries downloaded as JSON` });
          }}
          disabled={!data || entries.length === 0}
          aria-label="Export ledger entries as JSON"
        >
          <Download className="h-4 w-4" aria-hidden />
          Export JSON
        </Button>
      </div>

      {/* Integrity verification */}
      <div className="rounded-lg border bg-card/40 p-3.5">
        <VerifyBanner />
      </div>

      {/* Scan filter */}
      {scanTargets.length > 1 ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">Scan</span>
          <Select value={scanFilter} onValueChange={setScanFilter}>
            <SelectTrigger size="sm" className="w-[220px] border-zinc-700/60 bg-zinc-900/40 text-xs" aria-label="Filter ledger by scan target">
              <SelectValue placeholder="All scans" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All scans</SelectItem>
              {scanTargets.map((t) => (
                <SelectItem key={t} value={t} className="font-mono text-xs">
                  {truncateMiddle(t, 34)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      ) : null}

      {/* Entries */}
      {isLoading ? (
        <ListSkeleton rows={7} />
      ) : isError ? (
        <ErrorState
          title="Failed to load ledger"
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      ) : entries.length === 0 ? (
        <EmptyState
          icon={<ScrollText className="h-5 w-5" aria-hidden />}
          title="No ledger entries yet"
          description="Evidence is append-only written to the WORM ledger as scans collect and verify findings."
        />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<ScrollText className="h-5 w-5" aria-hidden />}
          title="No entries for this scan"
          description="Select a different scan target to inspect its evidence trail."
        />
      ) : (
        <div className={cn("transition-opacity", isFetching && "opacity-60")}>
          <LedgerTable entries={filtered} />
        </div>
      )}

      {/* Footer stats strip */}
      {entries.length > 0 ? (
        <div className="flex flex-col justify-between gap-2 rounded-lg border bg-card/40 px-4 py-2.5 text-[11px] text-zinc-500 sm:flex-row sm:items-center">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              <span className="font-mono text-zinc-300">{formatNumber(filtered.length)}</span> entries shown
            </span>
            <span aria-hidden>·</span>
            <span>
              <span className="font-mono text-zinc-300">{formatNumber(distinctFindings)}</span> findings
            </span>
            <span aria-hidden>·</span>
            <span>
              <span className="font-mono text-zinc-300">{formatNumber(distinctScans)}</span> scans
            </span>
          </div>
          <p className="font-mono text-[10px] text-zinc-600">
            append-only · hash-chained sha256 · exportable for SOC2/ISO27001
          </p>
        </div>
      ) : null}
    </div>
  );
}
