import { NextResponse, type NextRequest } from "next/server";

import { mutate } from "@/lib/swarm/server/scheduler";
import type { SchedulerMutationResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

const ACTIONS = new Set(["pause", "resume", "run-now", "delete", "create"]);

/**
 * POST /api/scheduler/mutate { action, id?, name?, cron?, format? } —
 * pause / resume / run-now / delete / create against the computed job set.
 * run-now appends a real EventLog row (type "scheduler") — deliveries land in
 * the audit trail, never as side-channel files.
 */
export async function POST(req: NextRequest) {
  try {
    const raw = (await req.json().catch(() => null)) as
      | { action?: unknown; id?: unknown; name?: unknown; cron?: unknown; format?: unknown }
      | null;

    const action = typeof raw?.action === "string" ? raw.action : "";
    if (!ACTIONS.has(action)) {
      return NextResponse.json(
        { ok: false, message: `invalid action '${action || "(missing)"}'` },
        { status: 400 }
      );
    }

    const id = typeof raw?.id === "string" ? raw.id.trim() : "";
    if (action !== "create" && !id) {
      return NextResponse.json(
        { ok: false, message: `missing job id for action '${action}'` },
        { status: 400 }
      );
    }

    const result = await mutate(action, id || undefined, {
      name: raw?.name,
      cron: raw?.cron,
      format: raw?.format,
    });

    if (!result.ok) {
      const status = result.code === "unknown-job" ? 404 : 400;
      return NextResponse.json({ ok: false, message: result.message }, { status });
    }

    const body: SchedulerMutationResponse = { ok: true, message: result.message };
    return NextResponse.json(body);
  } catch (err) {
    console.error("[api/scheduler/mutate] POST failed", err);
    return NextResponse.json({ error: "Scheduler mutation failed" }, { status: 500 });
  }
}
