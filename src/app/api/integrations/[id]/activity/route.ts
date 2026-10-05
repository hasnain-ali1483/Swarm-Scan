import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { integrationActivity } from "@/lib/swarm/server/integrations";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

/**
 * GET /api/integrations/:id/activity — newest-first audit trail for one
 * connector (test / dispatch / sync / toggle / config events).
 */
export async function GET(_req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const row = await db.integration.findUnique({ where: { id }, select: { key: true } });
  if (!row) {
    return NextResponse.json({ error: "Integration not found" }, { status: 404 });
  }
  const events = await integrationActivity(row.key, 20);
  return NextResponse.json({ events });
}
