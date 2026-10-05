import { NextResponse } from "next/server";
import { getEngineScans } from "@/lib/swarm/server/engine";

export const dynamic = "force-dynamic";

export async function GET() {
  const scans = await getEngineScans();
  return NextResponse.json({ scans });
}
