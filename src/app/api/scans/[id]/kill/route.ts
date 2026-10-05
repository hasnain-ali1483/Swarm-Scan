import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { ENGINE_UNREACHABLE, engineKill } from "@/lib/swarm/server/engine";
import type { EngineKillResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

const ACTIVE_STATUSES = ["running", "queued", "planning", "verifying"];

type Ctx = { params: Promise<{ id: string }> };

export async function POST(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const scan = await db.scan.findUnique({ where: { id }, select: { id: true, status: true } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (!ACTIVE_STATUSES.includes(scan.status)) {
    return NextResponse.json(
      { error: `Scan is not running (status: ${scan.status})` },
      { status: 409 }
    );
  }

  let response: EngineKillResponse;
  try {
    response = await engineKill(id);
  } catch (err) {
    // Kill must never silently fail: force the DB row to "killed" regardless.
    await db.scan.update({
      where: { id },
      data: { status: "killed", completedAt: new Date() },
    });
    await db.eventLog.create({
      data: {
        scanId: id,
        type: "kill",
        message: "Kill requested — engine unreachable, scan force-marked killed",
      },
    });
    const message = err instanceof Error ? err.message : ENGINE_UNREACHABLE;
    return NextResponse.json({ error: message }, { status: 502 });
  }

  // Idempotent upsert-style update — the engine ingest callback also sets this.
  await db.scan.update({
    where: { id },
    data: { status: "killed", completedAt: new Date() },
  });
  await db.eventLog.create({
    data: {
      scanId: id,
      type: "kill",
      message: `Scan killed — ${response.latencyMs}ms`,
      meta: JSON.stringify({ latencyMs: response.latencyMs }),
    },
  });
  return NextResponse.json(response);
}
