"use client";

// ─── Scan list — desktop table + mobile stacked cards ────────────────────────

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Eye, Globe, Lock, Plus, Radar, RotateCw, Square, Trash2, TriangleAlert } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { cn, formatDuration, formatNumber, timeAgo, truncateMiddle } from "@/lib/swarm/format";
import { api, type EngineKillResponse, type ScanSummary } from "@/lib/swarm/types";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { roleCan } from "@/lib/swarm/access-roles";
import {
  isScanActive,
  PolicyTierChip,
  ProfileChip,
  ProgressBar,
  ScanStatusBadge,
  SeverityDots,
} from "./status-badge";

function useScanMutations() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const killScan = async (scan: ScanSummary) => {
    try {
      const res = await api<EngineKillResponse>(`/api/scans/${scan.id}/kill`, {
        method: "POST",
      });
      toast({
        title: `SIGKILL propagated in ${res.latencyMs}ms`,
        description: res.message || "In-flight probes terminated. Evidence preserved.",
        variant: "destructive",
      });
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    } catch (err) {
      toast({
        title: "Kill failed",
        description: err instanceof Error ? err.message : "Engine unreachable",
        variant: "destructive",
      });
    }
  };

  const deleteScan = async (scan: ScanSummary) => {
    try {
      await api(`/api/scans/${scan.id}`, { method: "DELETE" });
      toast({ title: "Scan deleted", description: `${truncateMiddle(scan.target, 32)} removed.` });
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    } catch (err) {
      toast({
        title: "Delete failed",
        description: err instanceof Error ? err.message : "Control plane error",
        variant: "destructive",
      });
    }
  };

  return { killScan, deleteScan };
}

function ScanRowActions({
  scan,
  onOpen,
}: {
  scan: ScanSummary;
  onOpen: (id: string) => void;
}) {
  const { killScan, deleteScan } = useScanMutations();
  const [busy, setBusy] = useState(false);
  const active = isScanActive(scan.status);

  const run = (fn: (s: ScanSummary) => Promise<void>) => async () => {
    setBusy(true);
    try {
      await fn(scan);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center justify-end gap-0.5">
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7"
        aria-label={`Open scan ${scan.target}`}
        onClick={(e) => {
          e.stopPropagation();
          onOpen(scan.id);
        }}
      >
        <Eye className="h-3.5 w-3.5" aria-hidden />
      </Button>

      {active && (
        <span onClick={(e) => e.stopPropagation()} role="presentation">
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                disabled={busy}
                className="h-7 w-7 text-red-400 hover:bg-red-500/10 hover:text-red-400"
                aria-label={`Kill scan ${scan.target}`}
              >
                <Square className="h-3.5 w-3.5 fill-current" aria-hidden />
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent onClick={(e) => e.stopPropagation()}>
              <AlertDialogHeader>
                <AlertDialogTitle className="font-mono text-base">
                  Kill {truncateMiddle(scan.target, 40)}?
                </AlertDialogTitle>
                <AlertDialogDescription>
                  SIGKILL propagates to every in-flight probe on the execution plane
                  within 500 ms. The scan is marked <code>killed</code> and evidence
                  collected so far is preserved in the WORM ledger.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    void run(killScan)();
                  }}
                >
                  Kill scan
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </span>
      )}

      <span onClick={(e) => e.stopPropagation()} role="presentation">
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              disabled={busy}
              className="h-7 w-7 text-muted-foreground hover:bg-red-500/10 hover:text-red-400"
              aria-label={`Delete scan ${scan.target}`}
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent onClick={(e) => e.stopPropagation()}>
            <AlertDialogHeader>
              <AlertDialogTitle className="font-mono text-base">
                Delete {truncateMiddle(scan.target, 40)}?
              </AlertDialogTitle>
              <AlertDialogDescription>
                Permanently removes the scan plan, its agent runs, findings and
                evidence chain. This action cannot be undone.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  void run(deleteScan)();
                }}
              >
                Delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </span>
    </div>
  );
}

function DesktopScanTable({
  scans,
  onOpen,
}: {
  scans: ScanSummary[];
  onOpen: (id: string) => void;
}) {
  return (
    <div className="hidden overflow-x-auto rounded-xl border bg-card swarm-scroll md:block">
      <Table className="min-w-[1080px]">
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            {[
              "Target",
              "Status",
              "Profile",
              "Policy",
              "Progress",
              "Findings",
              "Requests",
              "Started",
              "Duration",
              "",
            ].map((h, i) => (
              <TableHead
                key={h + i}
                className="h-9 text-[11px] font-medium uppercase tracking-wider text-muted-foreground"
              >
                {h}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {scans.map((scan) => (
            <TableRow
              key={scan.id}
              tabIndex={0}
              className="cursor-pointer border-border/60 transition-colors hover:bg-muted/40 focus-visible:bg-muted/40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
              onClick={() => onOpen(scan.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onOpen(scan.id);
                }
              }}
              aria-label={`Open scan ${scan.target}`}
            >
              <TableCell className="max-w-[220px] py-2.5">
                <span className="flex items-center gap-2">
                  <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="truncate font-mono text-[13px] text-zinc-200">
                    {scan.target}
                  </span>
                </span>
              </TableCell>
              <TableCell className="py-2.5">
                <ScanStatusBadge status={scan.status} />
              </TableCell>
              <TableCell className="py-2.5">
                <ProfileChip profile={scan.profile} />
              </TableCell>
              <TableCell className="py-2.5">
                <PolicyTierChip tier={scan.policyTier} />
              </TableCell>
              <TableCell className="w-[130px] py-2.5">
                <ProgressBar value={scan.progress} active={isScanActive(scan.status)} />
              </TableCell>
              <TableCell className="py-2.5">
                <SeverityDots counts={scan.findingsBySeverity} />
              </TableCell>
              <TableCell className="py-2.5 font-mono text-xs text-zinc-400">
                {formatNumber(scan.requestCount)}
              </TableCell>
              <TableCell className="py-2.5 text-xs text-muted-foreground">
                {timeAgo(scan.startedAt ?? scan.createdAt)}
              </TableCell>
              <TableCell className="py-2.5 font-mono text-xs text-zinc-400">
                {formatDuration(scan.startedAt, scan.completedAt)}
              </TableCell>
              <TableCell className="py-2.5">
                <ScanRowActions scan={scan} onOpen={onOpen} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function MobileScanCards({
  scans,
  onOpen,
}: {
  scans: ScanSummary[];
  onOpen: (id: string) => void;
}) {
  return (
    <ul className="space-y-3 md:hidden">
      {scans.map((scan) => (
        <li key={scan.id}>
          <Card className="gap-3 rounded-xl px-4 py-3.5">
            <div className="flex items-start justify-between gap-2">
              <button
                type="button"
                className="min-w-0 text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary rounded-sm"
                onClick={() => onOpen(scan.id)}
                aria-label={`Open scan ${scan.target}`}
              >
                <span className="flex items-center gap-2">
                  <Globe className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
                  <span className="truncate font-mono text-[13px] text-zinc-200">
                    {scan.target}
                  </span>
                </span>
                <span className="mt-1.5 flex items-center gap-1.5">
                  <ProfileChip profile={scan.profile} />
                  <PolicyTierChip tier={scan.policyTier} />
                </span>
              </button>
              <ScanStatusBadge status={scan.status} />
            </div>
            <ProgressBar value={scan.progress} active={isScanActive(scan.status)} />
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-zinc-500">
              <SeverityDots counts={scan.findingsBySeverity} />
              <span>{formatNumber(scan.requestCount)} req</span>
              <span>{timeAgo(scan.startedAt ?? scan.createdAt)}</span>
              <span>{formatDuration(scan.startedAt, scan.completedAt)}</span>
            </div>
            <div className="-mr-1.5 flex justify-end">
              <ScanRowActions scan={scan} onOpen={onOpen} />
            </div>
          </Card>
        </li>
      ))}
    </ul>
  );
}

function EmptyScans({ onCreate }: { onCreate: () => void }) {
  const canLaunch = roleCan(useSwarmUi((s) => s.actingRole), "scans:launch");
  return (
    <Card className="items-center gap-4 rounded-xl border-dashed px-6 py-14">
      <span className="flex h-14 w-14 items-center justify-center rounded-full border border-primary/30 bg-primary/10">
        <Radar className="h-6 w-6 text-primary" aria-hidden />
      </span>
      <div className="text-center">
        <p className="text-sm font-medium text-foreground">No scans yet</p>
        <p className="mt-1 max-w-sm text-xs text-muted-foreground">
          Launch your first autonomous scan — the planner compiles a deterministic
          DAG from your profile, seed and policy tier.
        </p>
      </div>
      <Button
        size="sm"
        className="gap-2"
        onClick={onCreate}
        disabled={!canLaunch}
        title={canLaunch ? undefined : "scans:launch denied for this role — change the acting role in Access Control"}
      >
        {canLaunch ? <Plus className="h-4 w-4" aria-hidden /> : <Lock className="h-4 w-4" aria-hidden />}
        Launch New Scan
      </Button>
    </Card>
  );
}

export function ScanList({
  scans,
  isLoading,
  isError,
  error,
  onRetry,
  onCreate,
  onOpen,
}: {
  scans: ScanSummary[] | undefined;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  onRetry: () => void;
  onCreate: () => void;
  onOpen: (id: string) => void;
}) {
  const actingRole = useSwarmUi((s) => s.actingRole);
  const canLaunch = roleCan(actingRole, "scans:launch");
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-baseline gap-2.5">
          <h2 className="text-base font-semibold tracking-tight">Scan Plans</h2>
          <span className="font-mono text-xs text-muted-foreground">
            {isLoading ? "…" : `${scans?.length ?? 0} plan${scans?.length === 1 ? "" : "s"}`}
          </span>
        </div>
        <Button
          size="sm"
          className="gap-2"
          onClick={onCreate}
          disabled={!canLaunch}
          title={
            canLaunch
              ? undefined
              : `scans:launch denied for ${actingRole} — switch the acting role in Access Control`
          }
        >
          {canLaunch ? <Plus className="h-4 w-4" aria-hidden /> : <Lock className="h-4 w-4" aria-hidden />}
          New Scan
        </Button>
      </header>

      {isError ? (
        <Alert variant="destructive" role="alert">
          <TriangleAlert className="h-4 w-4" aria-hidden />
          <AlertTitle>Failed to load scans</AlertTitle>
          <AlertDescription className="flex flex-wrap items-center gap-3">
            <span className="font-mono text-xs">
              {error instanceof Error ? error.message : "Control plane unreachable"}
            </span>
            <Button size="sm" variant="outline" className="gap-1.5" onClick={onRetry}>
              <RotateCw className="h-3.5 w-3.5" aria-hidden />
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      ) : isLoading ? (
        <div className="space-y-3" aria-busy="true" aria-label="Loading scans">
          <Skeleton className="hidden h-[260px] rounded-xl md:block" />
          <Skeleton className="h-24 rounded-xl md:hidden" />
          <Skeleton className="h-24 rounded-xl md:hidden" />
        </div>
      ) : !scans || scans.length === 0 ? (
        <EmptyScans onCreate={onCreate} />
      ) : (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, ease: "easeOut" }}
          className={cn("space-y-3")}
        >
          <DesktopScanTable scans={scans} onOpen={onOpen} />
          <MobileScanCards scans={scans} onOpen={onOpen} />
        </motion.div>
      )}
    </div>
  );
}
