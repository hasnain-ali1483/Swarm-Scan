import { NextRequest, NextResponse } from "next/server";

import { getAccess, applyAccessAction } from "@/lib/swarm/server/access";
import type { AccessAction } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/** GET /api/access — full access-control surface (users, sessions, keys, SSO, matrix). */
export async function GET() {
  try {
    return NextResponse.json(await getAccess());
  } catch (err) {
    console.error("[api/access] GET failed", err);
    return NextResponse.json({ error: "Failed to load access state" }, { status: 500 });
  }
}

/** POST /api/access — Action union mutation. */
export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as AccessAction;
    if (!body || typeof body.action !== "string") {
      return NextResponse.json({ error: "Missing action" }, { status: 400 });
    }

    const actions = ["user.role", "user.status", "session.revoke", "key.create", "key.revoke", "sso.status"];
    if (!actions.includes(body.action)) {
      return NextResponse.json({ error: `Unknown action: ${body.action}` }, { status: 400 });
    }

    const result = await applyAccessAction(body);
    return NextResponse.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Access mutation failed";
    const status = /not found|Invalid|at least one/.test(message) ? 404 : 500;
    console.error("[api/access] POST failed", err);
    return NextResponse.json({ ok: false, error: message }, { status: 404 });
  }
}
