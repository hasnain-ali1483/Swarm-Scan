import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { engineKill, getEngineScans } from "@/lib/swarm/server/engine";
import {
  serializeAgentRun,
  serializeChain,
  serializeEvent,
  serializeFinding,
  serializeScan,
} from "@/lib/swarm/server/serialize";
import type { AgentRun, ScanDetail } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

const ACTIVE_STATUSES = ["running", "queued", "planning", "verifying"];

type Ctx = { params: Promise<{ id: string }> };

export async function GET(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const scan = await db.scan.findUnique({
    where: { id },
    include: {
      agentRuns: { orderBy: { createdAt: "asc" } },
      findings: { include: { evidence: true } },
      chains: true,
      events: { orderBy: { createdAt: "desc" }, take: 60 },
    },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  let status = scan.status;
  let progress = scan.progress;
  let requestCount = scan.requestCount;
  let agentRuns: AgentRun[] = scan.agentRuns.map(serializeAgentRun);

  // Merge live execution-plane state while the scan is in flight
  if (ACTIVE_STATUSES.includes(scan.status)) {
    const live = (await getEngineScans()).find((s) => s.scanId === scan.id);
    if (live) {
      status = live.status;
      progress = live.progress;
      requestCount = live.requestCount;
      const startedByAgent = new Map(
        scan.agentRuns.filter((r) => r.startedAt).map((r) => [r.agentKey, r.startedAt as Date])
      );
      agentRuns = (live.agents ?? []).map((a) => ({
        id: a.id ?? `${live.scanId}:${a.agentKey}`,
        scanId: live.scanId,
        agentKey: a.agentKey,
        agentName: a.agentName,
        version: a.version,
        state: a.state,
        status: a.status as AgentRun["status"],
        progress: a.progress,
        requests: a.requests,
        findings: a.findings,
        startedAt:
          (a.startedAt && new Date(a.startedAt).toISOString()) ??
          startedByAgent.get(a.agentKey)?.toISOString() ??
          scan.startedAt?.toISOString() ??
          null,
        endedAt: a.endedAt ? new Date(a.endedAt).toISOString() : null,
      }));
    }
  }

  const detail: ScanDetail = {
    ...serializeScan({ ...scan, status, progress, requestCount }),
    agentRuns,
    findings: scan.findings.map((f) =>
      serializeFinding({ ...f, scan: { id: scan.id, target: scan.target, status: scan.status } })
    ),
    chains: scan.chains.map(serializeChain),
    events: scan.events.map(serializeEvent),
  };
  return NextResponse.json(detail);
}

export async function DELETE(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id }, select: { id: true, status: true } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  // Best-effort: stop the engine copy first so it cannot re-ingest later.
  if (ACTIVE_STATUSES.includes(scan.status)) {
    try {
      await engineKill(id);
    } catch {
      /* engine down or scan not tracked there — proceed with DB delete */
    }
  }
  await db.scan.delete({ where: { id } }); // cascades to runs/findings/evidence/events/chains
  return NextResponse.json({ ok: true });
}
