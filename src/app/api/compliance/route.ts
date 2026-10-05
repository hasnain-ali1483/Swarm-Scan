import { NextResponse } from "next/server";

import { buildCompliancePack } from "@/lib/swarm/server/compliance";

export const dynamic = "force-dynamic";

/**
 * GET /api/compliance — the SOC 2 Type II evidence pack, assembled live from
 * the WORM ledger (control → evidence mapping + chain-head attestation).
 */
export async function GET() {
  try {
    const pack = await buildCompliancePack();
    return NextResponse.json(pack);
  } catch (err) {
    console.error("[api/compliance] GET failed", err);
    return NextResponse.json({ error: "Failed to build compliance pack" }, { status: 500 });
  }
}
