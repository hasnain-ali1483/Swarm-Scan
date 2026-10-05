"use client";

// ─── ScansView — scan plan list + detail routing ─────────────────────────────
// Owns the ["scans"] query. Live scan:update socket events are merged straight
// into the query cache so progress bars move smoothly without refetch storms.
// When the UI store holds a scanId, the detail view takes over.

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { api, type ScanSummary } from "@/lib/swarm/types";
import { useEngineSub } from "@/components/swarm/overview/use-engine-sub";
import { ScanList } from "@/components/swarm/scans/scan-list";
import { NewScanDialog } from "@/components/swarm/scans/new-scan-dialog";
import { ScanDetailView } from "@/components/swarm/scans/scan-detail-view";

export function ScansView() {
  const scanId = useSwarmUi((s) => s.scanId);
  const openScan = useSwarmUi((s) => s.openScan);
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);

  // Live merge: patch matching rows in the list cache.
  useEngineSub("scan:update", (u) => {
    queryClient.setQueryData<ScanSummary[]>(["scans"], (old) =>
      old
        ? old.map((s) =>
            s.id === u.scanId
              ? { ...s, status: u.status, progress: u.progress, requestCount: u.requestCount }
              : s
          )
        : old
    );
  });

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<ScanSummary[]>("/api/scans"),
    refetchInterval: 8_000,
  });

  if (scanId) {
    return <ScanDetailView scanId={scanId} />;
  }

  return (
    <div className="px-4 py-6 mx-auto w-full max-w-[1600px] lg:px-6">
      <ScanList
        scans={scans.data}
        isLoading={scans.isPending}
        isError={scans.isError}
        error={scans.error}
        onRetry={() => void scans.refetch()}
        onCreate={() => setCreateOpen(true)}
        onOpen={openScan}
      />

      <NewScanDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onLaunched={(scan) => {
          void queryClient.invalidateQueries({ queryKey: ["scans"] });
          void queryClient.invalidateQueries({ queryKey: ["overview"] });
          openScan(scan.id);
        }}
      />
    </div>
  );
}
