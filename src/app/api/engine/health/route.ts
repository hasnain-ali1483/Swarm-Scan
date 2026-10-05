import { NextResponse } from "next/server";
import { getEngineHealth } from "@/lib/swarm/server/engine";
import type { EngineHealthResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

export async function GET() {
  // never errors — an unreachable engine is a valid (down) health state
  const health: EngineHealthResponse = await getEngineHealth();
  return NextResponse.json(health);
}
