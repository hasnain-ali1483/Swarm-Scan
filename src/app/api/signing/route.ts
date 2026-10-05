import { NextResponse } from "next/server";

import { getSigning } from "@/lib/swarm/server/signing";

export const dynamic = "force-dynamic";

/** GET /api/signing — all registry bundles + supply-chain summary. */
export async function GET() {
  try {
    return NextResponse.json(getSigning());
  } catch (err) {
    console.error("[api/signing] GET failed", err);
    return NextResponse.json({ error: "Failed to load signing state" }, { status: 500 });
  }
}
