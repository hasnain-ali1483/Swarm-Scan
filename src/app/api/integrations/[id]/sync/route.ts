import { NextResponse, type NextRequest } from "next/server";
import { syncIntegration } from "@/lib/swarm/server/integrations";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

/**
 * POST /api/integrations/:id/sync — pull fresh context from an inbound source.
 * Guardrails: direction, enabled, required config, rate limit. Metric values
 * are seeded per (connector, 30s window) so they are deterministic within a
 * window and drift across windows.
 */
export async function POST(_req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const { status, body } = await syncIntegration(id);
  return NextResponse.json(body, { status });
}
