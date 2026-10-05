// ─── CI release gates — server evaluation (Task 8-a) ─────────────────────────
// Wires the benchmark corpus (spec §6 — "it's your CI") into agent-release
// gating: every catalog agent gets a gate verdict evaluated from its row in
// the LATEST benchmark run. An agent whose slice regresses below SLO
// (detection ≥ 90% AND FP < 2%) gets its registry release BLOCKED.
//
// Deterministic by construction: the verdict is a pure function of the
// persisted BenchmarkRun rows (same inputs ⇒ same status/metrics/note).
// Re-evaluating unchanged data is idempotent — verdictAt is kept and the
// route reports changed: 0.

import { db } from "@/lib/db";
import { AGENTS_CATALOG } from "@/lib/swarm/agents-catalog";
import type { CiGateRow, CiGatesResponse, CiGatesSummary, CiGateStatus } from "@/lib/swarm/types";

export const GATE_SLO = {
  detectionTarget: 90, // % — release requires detection ≥ 90%
  fpTarget: 2.0, // % — release requires FP < 2%
} as const;

const RUNNING_NOTE = "awaiting first benchmark run";

export interface CiGateEvaluation {
  gates: CiGateRow[];
  summary: CiGatesSummary;
  evaluated: number;
  changed: number;
}

interface GateVerdict {
  agentKey: string;
  agentName: string;
  releaseTag: string;
  runKey: string;
  status: CiGateStatus;
  detectionRate: number; // %
  fnRate: number; // %
  fpRate: number; // %
  durationMs: number;
  note: string;
}

const r1 = (x: number): number => Math.round(x * 10) / 10;

/**
 * Evaluate one agent's gate from its benchmark row (percent-space math).
 * A missing row means the agent has never been through the suite yet →
 * status "running" (gate pending, no verdict).
 */
function verdictFor(
  agent: { key: string; name: string; version: string },
  bench: { runKey: string; total: number; passed: number; failed: number; fpRate: number; durationMs: number } | undefined
): GateVerdict {
  const releaseTag = `${agent.key}@${agent.version}`;

  if (!bench || bench.total <= 0) {
    return {
      agentKey: agent.key,
      agentName: agent.name,
      releaseTag,
      runKey: "",
      status: "running",
      detectionRate: 0,
      fnRate: 0,
      fpRate: 0,
      durationMs: 0,
      note: RUNNING_NOTE,
    };
  }

  const detectionRate = r1((bench.passed / bench.total) * 100);
  const fnRate = r1((bench.failed / bench.total) * 100);
  const fpRate = r1(bench.fpRate * 100); // benchmark stores 0..1 fraction
  const detOk = detectionRate >= GATE_SLO.detectionTarget;
  const fpOk = fpRate < GATE_SLO.fpTarget;
  const passed = detOk && fpOk;

  return {
    agentKey: agent.key,
    agentName: agent.name,
    releaseTag,
    runKey: bench.runKey,
    status: passed ? "passed" : "failed",
    detectionRate,
    fnRate,
    fpRate,
    durationMs: bench.durationMs,
    note:
      `detection ${detectionRate.toFixed(1)}% ${detOk ? "≥" : "<"} ${GATE_SLO.detectionTarget}% · ` +
      `FP ${fpRate.toFixed(1)}% ${fpOk ? "<" : "≥"} ${GATE_SLO.fpTarget.toFixed(1)}% — ` +
      `release ${passed ? "unlocked" : "blocked"}`,
  };
}

/** Latest benchmark runKey group → per-agent rows (newest suite execution). */
async function latestBenchmarkRows(): Promise<Map<string, { runKey: string; total: number; passed: number; failed: number; fpRate: number; durationMs: number }>> {
  const newest = await db.benchmarkRun.findFirst({ orderBy: { createdAt: "desc" } });
  if (!newest) return new Map();
  const rows = await db.benchmarkRun.findMany({ where: { runKey: newest.runKey } });
  return new Map(
    rows.map((r) => [
      r.agentKey,
      { runKey: r.runKey, total: r.total, passed: r.passed, failed: r.failed, fpRate: r.fpRate, durationMs: r.durationMs },
    ])
  );
}

type PrismaCiGate = Awaited<ReturnType<typeof db.ciGate.findFirst>>;

function serializeGate(g: NonNullable<PrismaCiGate>): CiGateRow {
  return {
    id: g.id,
    agentKey: g.agentKey,
    agentName: g.agentName,
    releaseTag: g.releaseTag,
    runKey: g.runKey,
    status: g.status as CiGateStatus,
    detectionRate: g.detectionRate,
    fnRate: g.fnRate,
    fpRate: g.fpRate,
    durationMs: g.durationMs,
    verdictAt: g.verdictAt.toISOString(),
    note: g.note,
  };
}

function summarize(gates: CiGateRow[]): CiGatesSummary {
  const verdicts = gates.map((g) => g.verdictAt).sort().reverse();
  return {
    total: gates.length,
    passed: gates.filter((g) => g.status === "passed").length,
    failed: gates.filter((g) => g.status === "failed").length,
    lastEvaluatedAt: verdicts[0] ?? null,
  };
}

/** Read all persisted gates in catalog (DAG stage) order. */
async function readGates(): Promise<CiGateRow[]> {
  const rows = await db.ciGate.findMany();
  const byKey = new Map(rows.map((r) => [r.agentKey, r]));
  const ordered: CiGateRow[] = [];
  for (const agent of AGENTS_CATALOG) {
    const row = byKey.get(agent.key);
    if (row) ordered.push(serializeGate(row));
  }
  // passthrough for gates not in the catalog (future-proof)
  for (const row of rows) {
    if (!AGENTS_CATALOG.some((a) => a.key === row.agentKey)) ordered.push(serializeGate(row));
  }
  return ordered;
}

/**
 * Re-evaluate all 15 gates from the latest BenchmarkRun per agent, upsert by
 * (agentKey, releaseTag). Idempotent: an unchanged status+metrics verdict
 * keeps its original verdictAt (changed counts only real verdict flips or
 * metric moves).
 */
export async function evaluateCiGates(): Promise<CiGateEvaluation> {
  const bench = await latestBenchmarkRows();
  const existing = await db.ciGate.findMany();
  const existingByKey = new Map(existing.map((g) => [`${g.agentKey}::${g.releaseTag}`, g]));

  const now = new Date();
  let changed = 0;
  const persisted: NonNullable<PrismaCiGate>[] = [];

  for (const agent of AGENTS_CATALOG) {
    const verdict = verdictFor(agent, bench.get(agent.key));
    const prev = existingByKey.get(`${verdict.agentKey}::${verdict.releaseTag}`);
    const unchanged =
      prev !== undefined &&
      prev.status === verdict.status &&
      prev.detectionRate === verdict.detectionRate &&
      prev.fnRate === verdict.fnRate &&
      prev.fpRate === verdict.fpRate;

    if (unchanged) {
      persisted.push(prev);
      continue;
    }

    const row = await db.ciGate.upsert({
      where: { agentKey_releaseTag: { agentKey: verdict.agentKey, releaseTag: verdict.releaseTag } },
      create: {
        agentKey: verdict.agentKey,
        agentName: verdict.agentName,
        releaseTag: verdict.releaseTag,
        runKey: verdict.runKey,
        status: verdict.status,
        detectionRate: verdict.detectionRate,
        fnRate: verdict.fnRate,
        fpRate: verdict.fpRate,
        durationMs: verdict.durationMs,
        verdictAt: now,
        note: verdict.note,
      },
      update: {
        agentName: verdict.agentName,
        runKey: verdict.runKey,
        status: verdict.status,
        detectionRate: verdict.detectionRate,
        fnRate: verdict.fnRate,
        fpRate: verdict.fpRate,
        durationMs: verdict.durationMs,
        verdictAt: now,
        note: verdict.note,
      },
    });
    persisted.push(row);
    changed += 1;
  }

  const gates = persisted.map(serializeGate);
  return {
    gates,
    summary: summarize(gates),
    evaluated: persisted.length,
    changed,
  };
}

/**
 * Read gates; deterministically bootstrap-evaluate from the latest benchmark
 * run per agent when the table is empty (first visit before any evaluate).
 */
export async function getCiGates(): Promise<CiGatesResponse> {
  const count = await db.ciGate.count();
  if (count === 0) {
    const { gates, summary } = await evaluateCiGates();
    return { gates, summary };
  }
  const gates = await readGates();
  return { gates, summary: summarize(gates) };
}
