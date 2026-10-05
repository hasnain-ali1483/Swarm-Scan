import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { ENGINE_UNREACHABLE, engineKill } from "@/lib/swarm/server/engine";

export const dynamic = "force-dynamic";

export async function POST() {
  try {
    const response = await engineKill();
    await db.eventLog.create({
      data: {
        type: "kill",
        message: `Global kill switch engaged — ${response.latencyMs}ms`,
        meta: JSON.stringify({ latencyMs: response.latencyMs }),
      },
    });
    return NextResponse.json(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : ENGINE_UNREACHABLE;
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
