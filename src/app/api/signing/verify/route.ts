import { NextRequest, NextResponse } from "next/server";

import { verifyBundle } from "@/lib/swarm/server/signing";

export const dynamic = "force-dynamic";

/**
 * POST /api/signing/verify — { agentKey, releaseTag } → SignVerifyResponse.
 * Runs the Sigstore/SLSA verification checklist (deterministic step results,
 * realistic per-step latency).
 */
export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as { agentKey?: string; releaseTag?: string };
    if (!body?.agentKey || !body?.releaseTag) {
      return NextResponse.json({ error: "agentKey and releaseTag are required" }, { status: 400 });
    }
    const result = await verifyBundle(body.agentKey, body.releaseTag);
    return NextResponse.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Verification failed";
    const status = message.startsWith("No bundle") ? 404 : 500;
    console.error("[api/signing/verify] POST failed", err);
    return NextResponse.json({ error: message }, { status });
  }
}
