import { NextResponse } from "next/server";
import { getCiGates } from "@/lib/swarm/server/ci-gates";

export const dynamic = "force-dynamic";

/** GET /api/ci-gates — all release gates; bootstraps from the latest benchmark run if empty. */
export async function GET() {
  try {
    const body = await getCiGates();
    return NextResponse.json(body);
  } catch (err) {
    console.error("[api/ci-gates] GET failed", err);
    return NextResponse.json({ error: "Failed to load CI gates" }, { status: 500 });
  }
}
