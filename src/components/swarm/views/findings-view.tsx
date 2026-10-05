"use client";

// ─── Findings view ────────────────────────────────────────────────────────────
// Routes between the findings list and the finding detail based on the UI store.

import { useSwarmUi } from "@/lib/swarm/ui-store";
import { FindingDetail } from "@/components/swarm/findings/finding-detail";
import { FindingsList } from "@/components/swarm/findings/findings-list";

export function FindingsView() {
  const findingId = useSwarmUi((s) => s.findingId);

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px]">
      {findingId ? <FindingDetail findingId={findingId} /> : <FindingsList />}
    </div>
  );
}
