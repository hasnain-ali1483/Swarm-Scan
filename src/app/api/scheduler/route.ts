import { NextResponse } from "next/server";

import { listJobs } from "@/lib/swarm/server/scheduler";
import type { SchedulerListResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/** GET /api/scheduler — export jobs with live-computed nextRunAt from cron. */
export async function GET() {
  try {
    const body: SchedulerListResponse = { jobs: listJobs() };
    return NextResponse.json(body);
  } catch (err) {
    console.error("[api/scheduler] GET failed", err);
    return NextResponse.json({ error: "Failed to list scheduler jobs" }, { status: 500 });
  }
}
