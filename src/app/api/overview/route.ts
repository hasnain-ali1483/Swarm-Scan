import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { AGENTS_CATALOG } from "@/lib/swarm/agents-catalog";
import { getEngineHealth } from "@/lib/swarm/server/engine";
import { serializeEvent, serializeFinding } from "@/lib/swarm/server/serialize";
import type { ConfidenceBand, OverviewResponse, Severity } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

const ACTIVE_STATUSES = ["running", "queued", "planning", "verifying"];

/**
 * Real benchmark-derived quality metrics from the most recent suite run:
 *   fpRate        = mean false-positive rate, as a percentage
 *   detectionRate = mean recall (1 − fnRate), as a percentage
 * Both null when the corpus has never been run — the UI shows "not measured"
 * rather than a fabricated number.
 */
async function computeBenchmarkMetrics(): Promise<{ fpRate: number | null; detectionRate: number | null }> {
  const latest = await db.benchmarkRun.findFirst({ orderBy: { createdAt: "desc" }, select: { runKey: true } });
  if (!latest) return { fpRate: null, detectionRate: null };
  const rows = await db.benchmarkRun.findMany({ where: { runKey: latest.runKey }, select: { fpRate: true, fnRate: true } });
  if (rows.length === 0) return { fpRate: null, detectionRate: null };
  const meanFp = rows.reduce((a, r) => a + r.fpRate, 0) / rows.length;
  const meanFn = rows.reduce((a, r) => a + r.fnRate, 0) / rows.length;
  return {
    fpRate: Math.round(meanFp * 100 * 10) / 10,
    detectionRate: Math.round((1 - meanFn) * 100 * 10) / 10,
  };
}

export async function GET() {
  const [
    totalScans,
    dbActiveScans,
    severityGroups,
    bandGroups,
    runGroups,
    findingGroups,
    recentFindings,
    recentEvents,
    engineHealth,
  ] = await Promise.all([
    db.scan.count(),
    db.scan.count({ where: { status: { in: ACTIVE_STATUSES } } }),
    db.finding.groupBy({ by: ["severity"], _count: { _all: true } }),
    db.finding.groupBy({ by: ["band"], _count: { _all: true } }),
    db.agentRun.groupBy({ by: ["agentKey"], _count: { _all: true }, _sum: { findings: true } }),
    db.finding.groupBy({ by: ["agentKey"], _count: { _all: true }, _avg: { confidence: true } }),
    db.finding.findMany({
      orderBy: { createdAt: "desc" },
      take: 8,
      include: { scan: { select: { id: true, target: true, status: true } } },
    }),
    db.eventLog.findMany({ orderBy: { createdAt: "desc" }, take: 12 }),
    getEngineHealth(),
  ]);

  const { fpRate, detectionRate } = await computeBenchmarkMetrics();

  // killLatencyMs: engine health first, then latest kill event meta, else 0
  let killLatencyMs = engineHealth.lastKillLatencyMs;
  if (killLatencyMs == null) {
    const lastKill = await db.eventLog.findFirst({
      where: { type: "kill" },
      orderBy: { createdAt: "desc" },
    });
    if (lastKill?.meta) {
      try {
        const meta = JSON.parse(lastKill.meta) as { latencyMs?: number };
        if (typeof meta.latencyMs === "number") killLatencyMs = meta.latencyMs;
      } catch {
        /* non-JSON meta — ignore */
      }
    }
  }

  const severity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const g of severityGroups) {
    if (g.severity in severity) severity[g.severity as Severity] = g._count._all;
  }

  const bands: Record<ConfidenceBand, number> = { suspected: 0, likely: 0, confirmed: 0 };
  for (const g of bandGroups) {
    if (g.band in bands) bands[g.band as ConfidenceBand] = g._count._all;
  }

  const runsByAgent = new Map(runGroups.map((g) => [g.agentKey, g]));
  const findingsByAgent = new Map(findingGroups.map((g) => [g.agentKey, g]));
  const agentActivity = AGENTS_CATALOG.map((agent) => {
    const run = runsByAgent.get(agent.key);
    const finding = findingsByAgent.get(agent.key);
    return {
      agentKey: agent.key,
      name: agent.name,
      runs: run?._count._all ?? 0,
      findings: run?._sum.findings ?? 0,
      avgConfidence: Math.round((finding?._avg.confidence ?? 0) * 10) / 10,
    };
  });

  const totalFindings = Object.values(severity).reduce((a, b) => a + b, 0);

  const body: OverviewResponse = {
    kpis: {
      activeScans: Math.max(dbActiveScans, engineHealth.activeScans),
      totalScans,
      // engine health may expose requestsPerMin beyond the base contract
      requestsPerMin:
        (engineHealth as unknown as { requestsPerMin?: number }).requestsPerMin ?? 0,
      killLatencyMs: killLatencyMs ?? 0,
      fpRate,
      detectionRate,
      confirmedFindings: bands.confirmed,
      totalFindings,
    },
    severity,
    bands,
    agentActivity,
    recentFindings: recentFindings.map(serializeFinding),
    recentEvents: recentEvents.map(serializeEvent),
    engine: {
      healthy: engineHealth.ok,
      activeScans: engineHealth.activeScans,
      workers: engineHealth.workers,
      uptimeSec: engineHealth.uptimeSec,
      tools: engineHealth.tools ?? [],
    },
  };
  return NextResponse.json(body);
}
