import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { runSuite, SLO } from "@/lib/swarm/benchmark";
import type { BenchmarkRunResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/** POST /api/benchmark/run — execute the 500-case suite, persist per-agent rows. */
export async function POST() {
  try {
    const seed = Math.random().toString(16).slice(2, 10);
    const runKey = `bench-${Date.now().toString(36)}-${seed}`;
    const results = runSuite(seed);

    const created = await Promise.all(
      results.map((r) =>
        db.benchmarkRun.create({
          data: {
            runKey,
            agentKey: r.agentKey,
            agentName: r.agentName,
            total: r.total,
            passed: r.passed,
            failed: r.failed,
            fnRate: r.fnRate,
            fpRate: r.fpRate,
            durationMs: r.durationMs,
            seed,
          },
        })
      )
    );

    const total = results.reduce((a, r) => a + r.total, 0);
    const passed = results.reduce((a, r) => a + r.passed, 0);
    const failed = results.reduce((a, r) => a + r.failed, 0);
    const fpWeighted = results.reduce((a, r) => a + r.fpRate * r.total, 0) / Math.max(1, total);
    const detectionRate = passed / Math.max(1, total);

    const body: BenchmarkRunResponse = {
      runKey,
      seed,
      rows: created.map((r) => ({
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
      })),
      aggregate: {
        total,
        passed,
        failed,
        fnRate: Math.round((failed / Math.max(1, total)) * 1000) / 1000,
        fpRate: Math.round(fpWeighted * 1000) / 1000,
        detectionRate: Math.round(detectionRate * 1000) / 1000,
        durationMs: results.reduce((a, r) => a + r.durationMs, 0),
        sloMet: detectionRate >= SLO.fnTarget && fpWeighted < SLO.fpTarget,
      },
    };
    return NextResponse.json(body);
  } catch (err) {
    console.error("[api/benchmark/run] POST failed", err);
    return NextResponse.json({ error: "Benchmark run failed" }, { status: 500 });
  }
}
