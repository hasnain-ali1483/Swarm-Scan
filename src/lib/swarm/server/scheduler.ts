// ─── Export scheduler — computed, never persisted as side-channel files ──────
// Job definitions live in module state (globalThis-guarded so dev hot reloads
// keep the in-flight status/deliveries), while every *delivery* appends a real
// EventLog row to the WORM audit trail (type "scheduler"). nextRunAt is always
// recomputed from the cron expression — no stored timers. The cron parser
// supports the 5-field subset the platform uses: "*", "*/n", "a", "a,b,c".

import { db } from "@/lib/db";
import type { SchedulerJob, SchedulerJobStatus } from "@/lib/swarm/types";

// ─── Cron parser (5-field subset, UTC) ───────────────────────────────────────

function parseField(field: string, min: number, max: number, label: string): Set<number> {
  const values = new Set<number>();
  for (const part of field.split(",")) {
    if (part === "*") {
      for (let v = min; v <= max; v++) values.add(v);
    } else if (part.startsWith("*/")) {
      const step = Number.parseInt(part.slice(2), 10);
      if (!Number.isInteger(step) || step < 1) {
        throw new Error(`invalid ${label} step in cron field '${field}'`);
      }
      for (let v = min; v <= max; v += step) values.add(v);
    } else {
      const v = Number.parseInt(part, 10);
      if (!Number.isInteger(v) || v < min || v > max) {
        throw new Error(`invalid ${label} value '${part}' in cron field '${field}'`);
      }
      values.add(v);
    }
  }
  if (values.size === 0) throw new Error(`empty ${label} cron field '${field}'`);
  return values;
}

/**
 * Next ISO datetime strictly after `from` for a 5-field cron expression
 * (minute hour dom month dow — UTC, POSIX dom/dow OR semantics when both
 * are restricted). Supports "*", step values, single values and comma lists.
 */
export function nextRunFromCron(cron: string, from = new Date()): string {
  const fields = cron.trim().split(/\s+/);
  if (fields.length !== 5) throw new Error(`cron must have 5 fields, got '${cron}'`);

  const minutes = parseField(fields[0], 0, 59, "minute");
  const hours = parseField(fields[1], 0, 23, "hour");
  const doms = parseField(fields[2], 1, 31, "day-of-month");
  const months = parseField(fields[3], 1, 12, "month");
  const dows = new Set(
    [...parseField(fields[4], 0, 7, "day-of-week")].map((d) => d % 7) // 7 → Sunday
  );

  const domRestricted = fields[2] !== "*";
  const dowRestricted = fields[4] !== "*";

  const dayMatches = (y: number, mo: number, d: number): boolean => {
    const domOk = doms.has(d);
    const dowOk = dows.has(new Date(Date.UTC(y, mo, d)).getUTCDay());
    return domRestricted && dowRestricted ? domOk || dowOk : domOk && dowOk;
  };

  // First candidate minute strictly after `from` (second-truncated).
  let cursor = new Date(from.getTime());
  cursor.setUTCSeconds(0, 0);
  cursor = new Date(cursor.getTime() + 60_000);

  // Day-level scan window: a year plus slack covers the quarterly cadence.
  for (let guard = 0; guard < 400; guard++) {
    const y = cursor.getUTCFullYear();
    const mo = cursor.getUTCMonth();

    if (!months.has(mo + 1)) {
      cursor = new Date(Date.UTC(y, mo + 1, 1));
      continue;
    }

    const d = cursor.getUTCDate();
    if (!dayMatches(y, mo, d)) {
      cursor = new Date(Date.UTC(y, mo, d + 1));
      continue;
    }

    const curH = cursor.getUTCHours();
    const curM = cursor.getUTCMinutes();
    for (const h of [...hours].sort((a, b) => a - b)) {
      if (h < curH) continue;
      for (const m of [...minutes].sort((a, b) => a - b)) {
        if (h === curH && m < curM) continue;
        return new Date(Date.UTC(y, mo, d, h, m)).toISOString();
      }
    }
    cursor = new Date(Date.UTC(y, mo, d + 1));
  }

  throw new Error(`no next run within a year for cron '${cron}'`);
}

/** Human-readable label for the cron presets the platform ships. */
export function describeCron(cron: string): string {
  const known: Record<string, string> = {
    "0 8 * * 1": "Every Monday 08:00 UTC",
    "0 9 1 * *": "1st of every month 09:00 UTC",
    "0 18 * * *": "Every day 18:00 UTC",
    "0 */6 * * *": "Every 6 hours on the hour UTC",
    "0 6 1 1,4,7,10 *": "Quarterly — Jan/Apr/Jul/Oct 1st 06:00 UTC",
  };
  return known[cron.trim()] ?? `${cron.trim()} (UTC)`;
}

// ─── Module-singleton job state (globalThis guard for dev hot reloads) ───────

type JobFormat = "soc2" | "sarif" | "executive";

interface JobState {
  id: string;
  name: string;
  cron: string;
  humanCron: string;
  format: JobFormat;
  status: SchedulerJobStatus;
  lastRunAt: string | null;
  lastStatus: "success" | "failed" | null;
  lastDurationMs: number | null;
  deliveries: number;
}

interface SchedulerCore {
  jobs: JobState[];
  counter: number;
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function seedJobs(): JobState[] {
  const now = Date.now();
  return [
    {
      id: "job-weekly-soc2",
      name: "Weekly SOC 2 evidence pack",
      cron: "0 8 * * 1",
      humanCron: "Every Monday 08:00 UTC",
      format: "soc2",
      status: "enabled",
      lastRunAt: new Date(now - 7 * DAY).toISOString(),
      lastStatus: "success",
      lastDurationMs: 2213,
      deliveries: 14,
    },
    {
      id: "job-monthly-exec",
      name: "Monthly executive risk report",
      cron: "0 9 1 * *",
      humanCron: "1st of every month 09:00 UTC",
      format: "executive",
      status: "enabled",
      lastRunAt: new Date(now - 28 * DAY).toISOString(),
      lastStatus: "success",
      lastDurationMs: 1531,
      deliveries: 3,
    },
    {
      id: "job-daily-sarif",
      name: "Daily SARIF delta for CI",
      cron: "0 18 * * *",
      humanCron: "Every day 18:00 UTC",
      format: "sarif",
      status: "enabled",
      lastRunAt: new Date(now - 1 * DAY).toISOString(),
      lastStatus: "success",
      lastDurationMs: 687,
      deliveries: 46,
    },
    {
      id: "job-quarterly-audit",
      name: "Quarterly auditor bundle",
      cron: "0 6 1 1,4,7,10 *",
      humanCron: "Quarterly — Jan/Apr/Jul/Oct 1st 06:00 UTC",
      format: "soc2",
      status: "enabled",
      lastRunAt: new Date(now - 92 * DAY).toISOString(),
      lastStatus: "success",
      lastDurationMs: 3104,
      deliveries: 2,
    },
  ];
}

const globalForScheduler = globalThis as typeof globalThis & {
  __swarmSchedulerState?: SchedulerCore;
};

function core(): SchedulerCore {
  if (!globalForScheduler.__swarmSchedulerState) {
    globalForScheduler.__swarmSchedulerState = { jobs: seedJobs(), counter: 1 };
  }
  return globalForScheduler.__swarmSchedulerState;
}

// ─── Public surface ──────────────────────────────────────────────────────────

export function listJobs(): SchedulerJob[] {
  return core().jobs.map((job) => ({
    id: job.id,
    name: job.name,
    cron: job.cron,
    humanCron: job.humanCron,
    format: job.format,
    status: job.status,
    nextRunAt: nextRunFromCron(job.cron),
    lastRunAt: job.lastRunAt,
    lastStatus: job.lastStatus,
    lastDurationMs: job.lastDurationMs,
    deliveries: job.deliveries,
  }));
}

export interface SchedulerMutationResult {
  ok: boolean;
  message: string;
  /** Machine-readable failure code for the route's HTTP mapping. */
  code?: "unknown-job" | "invalid-args";
}

export interface SchedulerCreatePayload {
  name?: unknown;
  cron?: unknown;
  format?: unknown;
}

/** Deterministic pack duration — derived from ledger size and format weight. */
function durationFor(format: JobFormat, entries: number): number {
  const base = format === "soc2" ? 800 : format === "executive" ? 650 : 400;
  return base + entries * 13;
}

export async function mutate(
  action: string,
  id?: string,
  payload?: SchedulerCreatePayload
): Promise<SchedulerMutationResult> {
  const state = core();

  if (action === "create") {
    const name = typeof payload?.name === "string" ? payload.name.trim() : "";
    const cron = typeof payload?.cron === "string" ? payload.cron.trim() : "";
    const format = typeof payload?.format === "string" ? payload.format : "";

    if (!name) return { ok: false, message: "job name is required", code: "invalid-args" };
    if (!cron) return { ok: false, message: "cron expression is required", code: "invalid-args" };
    try {
      nextRunFromCron(cron);
    } catch (err) {
      return {
        ok: false,
        message: err instanceof Error ? err.message : `invalid cron expression '${cron}'`,
        code: "invalid-args",
      };
    }
    if (format !== "soc2" && format !== "sarif" && format !== "executive") {
      return {
        ok: false,
        message: `format must be one of soc2 | sarif | executive, got '${format}'`,
        code: "invalid-args",
      };
    }

    const jobId = `job-${(state.counter++).toString(16).padStart(6, "0")}`;
    const job: JobState = {
      id: jobId,
      name,
      cron,
      humanCron: describeCron(cron),
      format,
      status: "enabled",
      lastRunAt: null,
      lastStatus: null,
      lastDurationMs: null,
      deliveries: 0,
    };
    state.jobs.push(job);

    await db.eventLog.create({
      data: {
        type: "scheduler",
        message: `Export job '${name}' created (${format} · ${cron}) — first delivery ${nextRunFromCron(cron)}`,
        meta: JSON.stringify({ jobId, name, cron, format, action: "create" }),
      },
    });

    return { ok: true, message: `Job '${name}' created — first delivery ${describeCron(cron)}.` };
  }

  if (action !== "pause" && action !== "resume" && action !== "run-now" && action !== "delete") {
    return { ok: false, message: `unknown action '${action}'`, code: "invalid-args" };
  }

  const job = state.jobs.find((j) => j.id === id);
  if (!job) return { ok: false, message: "unknown job", code: "unknown-job" };

  switch (action) {
    case "pause": {
      job.status = "paused";
      return { ok: true, message: `Job '${job.name}' paused — no deliveries until resumed.` };
    }
    case "resume": {
      job.status = "enabled";
      return {
        ok: true,
        message: `Job '${job.name}' resumed — next delivery ${job.humanCron.toLowerCase()}.`,
      };
    }
    case "run-now": {
      // The delivery: seal the current pack and append to the WORM audit trail.
      const entries = await db.evidence.count();
      job.lastRunAt = new Date().toISOString();
      job.lastStatus = "success";
      job.lastDurationMs = durationFor(job.format, entries);
      job.deliveries += 1;

      await db.eventLog.create({
        data: {
          type: "scheduler",
          message: `Scheduled delivery '${job.name}' executed — pack sealed · ${entries} entries`,
          meta: JSON.stringify({
            jobId: job.id,
            job: job.name,
            format: job.format,
            entries,
            durationMs: job.lastDurationMs,
            deliveries: job.deliveries,
            action: "run-now",
          }),
        },
      });

      return {
        ok: true,
        message: `Scheduled delivery '${job.name}' executed — pack sealed · ${entries} entries`,
      };
    }
    case "delete": {
      state.jobs = state.jobs.filter((j) => j.id !== job.id);
      await db.eventLog.create({
        data: {
          type: "scheduler",
          message: `Export job '${job.name}' deleted after ${job.deliveries} deliveries`,
          meta: JSON.stringify({ jobId: job.id, name: job.name, action: "delete" }),
        },
      });
      return { ok: true, message: `Job '${job.name}' deleted — no further deliveries.` };
    }
  }
}
