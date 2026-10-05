import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { corpus, corpusSlices, SLO } from "@/lib/swarm/benchmark";
import type { BenchmarkSummaryResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/** GET /api/benchmark — corpus summary + latest suite run + history. */
export async function GET() {
  try {
    const cases = corpus();

    const bySourceMap = new Map<string, number>();
    const bySeverity: Record<string, number> = {};
    const byDifficulty: Record<string, number> = {};
    for (const c of cases) {
      bySourceMap.set(c.source, (bySourceMap.get(c.source) ?? 0) + 1);
      bySeverity[c.severity] = (bySeverity[c.severity] ?? 0) + 1;
      byDifficulty[c.difficulty] = (byDifficulty[c.difficulty] ?? 0) + 1;
    }

    const rows = await db.benchmarkRun.findMany({
      orderBy: { createdAt: "desc" },
      take: 240,
    });

    // Group rows into runs (latest first by runKey ordering of first row).
    const runOrder: string[] = [];
    const runMap = new Map<string, typeof rows>();
    for (const r of rows) {
      if (!runMap.has(r.runKey)) {
        runMap.set(r.runKey, []);
        runOrder.push(r.runKey);
      }
      runMap.get(r.runKey)!.push(r);
    }

    const history = runOrder.slice(0, 12).map((key) => {
      const rs = runMap.get(key)!;
      const total = rs.reduce((a, r) => a + r.total, 0);
      const passed = rs.reduce((a, r) => a + r.passed, 0);
      const fpWeighted = rs.reduce((a, r) => a + r.fpRate * r.total, 0) / Math.max(1, total);
      const detectionRate = passed / Math.max(1, total);
      return {
        runKey: key,
        createdAt: rs[0].createdAt.toISOString(),
        detectionRate: Math.round(detectionRate * 1000) / 1000,
        fpRate: Math.round(fpWeighted * 1000) / 1000,
        sloMet: detectionRate >= SLO.fnTarget && fpWeighted < SLO.fpTarget,
      };
    });

    let latestRun: BenchmarkSummaryResponse["latestRun"] = null;
    if (runOrder.length > 0) {
      const key = runOrder[0];
      const rs = runMap.get(key)!;
      const total = rs.reduce((a, r) => a + r.total, 0);
      const passed = rs.reduce((a, r) => a + r.passed, 0);
      const failed = rs.reduce((a, r) => a + r.failed, 0);
      const fpWeighted = rs.reduce((a, r) => a + r.fpRate * r.total, 0) / Math.max(1, total);
      const detectionRate = passed / Math.max(1, total);
      latestRun = {
        runKey: key,
        seed: rs[0].seed,
        createdAt: rs[0].createdAt.toISOString(),
        rows: rs
          .map((r) => ({
            id: r.id,
            runKey: r.runKey,
            agentKey: r.agentKey,
            agentName: r.agentName,
            total: r.total,
            passed: r.passed,
            failed: r.failed,
            fnRate: r.fnRate,
            fpRate: r.fpRate,
            durationMs: r.durationMs,
            seed: r.seed,
            createdAt: r.createdAt.toISOString(),
          }))
          .sort((a, b) => b.failed - a.failed || b.fnRate - a.fnRate),
        aggregate: {
          total,
          passed,
          failed,
          fnRate: Math.round((failed / Math.max(1, total)) * 1000) / 1000,
          fpRate: Math.round(fpWeighted * 1000) / 1000,
          detectionRate: Math.round(detectionRate * 1000) / 1000,
          durationMs: rs.reduce((a, r) => a + r.durationMs, 0),
          sloMet: detectionRate >= SLO.fnTarget && fpWeighted < SLO.fpTarget,
        },
      };
    }

    const body: BenchmarkSummaryResponse & {
      slices: ReturnType<typeof corpusSlices>;
    } = {
      totalCases: cases.length,
      agents: corpusSlices().length,
      bySource: [...bySourceMap.entries()]
        .map(([source, count]) => ({ source, count }))
        .sort((a, b) => b.count - a.count),
      bySeverity,
      byDifficulty,
      slo: { fnTarget: SLO.fnTarget, fpTarget: SLO.fpTarget },
      latestRun,
      history,
      slices: corpusSlices(),
    };
    return NextResponse.json(body);
  } catch (err) {
    console.error("[api/benchmark] GET failed", err);
    return NextResponse.json({ error: "Failed to load benchmark summary" }, { status: 500 });
  }
}
