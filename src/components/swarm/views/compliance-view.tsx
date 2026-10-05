"use client";

// ─── Compliance view — 17th view (Task 11-b) ─────────────────────────────────
// SOC 2 Type II evidence packs cut from the WORM ledger: control matrix with
// chain-head attestation, an export builder (RBAC-gated on reports:export)
// and the export scheduler (RBAC-gated on scheduler:manage) whose deliveries
// land in the EventLog audit trail.

import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/swarm/findings/states";
import { ComplianceHeader } from "@/components/swarm/compliance/compliance-header";
import { ControlMatrix } from "@/components/swarm/compliance/control-matrix";
import { ExportBuilder } from "@/components/swarm/compliance/export-builder";
import { SchedulerPanel } from "@/components/swarm/compliance/scheduler-panel";
import { useCompliance } from "@/components/swarm/compliance/use-compliance";

export function ComplianceView() {
  const { data: pack, isLoading, error, refetch, isFetching } = useCompliance();

  if (error) {
    return (
      <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px]">
        <ErrorState
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => void refetch()}
          retrying={isFetching}
          title="Failed to assemble the compliance pack"
        />
      </div>
    );
  }

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px]">
      {isLoading || !pack ? (
        <div className="space-y-5">
          <div className="space-y-4">
            <Skeleton className="h-10 w-2/3" />
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-[62px] rounded-lg" />
              ))}
            </div>
          </div>
          <div className="grid gap-5 lg:grid-cols-[1fr_360px]">
            <div className="grid gap-4 lg:grid-cols-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-64 rounded-lg" />
              ))}
            </div>
            <div className="space-y-5">
              <Skeleton className="h-72 rounded-lg" />
              <Skeleton className="h-96 rounded-lg" />
            </div>
          </div>
        </div>
      ) : (
        <>
          <ComplianceHeader pack={pack} />

          <div className="mt-5 grid min-w-0 gap-5 lg:grid-cols-[1fr_360px]">
            <div className="min-w-0">
              <ControlMatrix controls={pack.controls} />
            </div>
            <div className="min-w-0 space-y-5">
              <ExportBuilder pack={pack} />
              <SchedulerPanel />
            </div>
          </div>

          <p className="mt-4 font-mono text-[10px] text-zinc-600">
            {pack.framework} · rolling quarter {pack.periodStart.slice(0, 10)} →{" "}
            {pack.periodEnd.slice(0, 10)} · chain head {pack.summary.chainHead.slice(0, 16)}… ·
            evidence ledger {pack.summary.evidenceEntries} entries
          </p>
        </>
      )}
    </div>
  );
}
