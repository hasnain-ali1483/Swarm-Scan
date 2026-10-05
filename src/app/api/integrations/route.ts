import { NextResponse } from "next/server";
import { provisionAndList } from "@/lib/swarm/server/integrations";
import type { IntegrationsResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/**
 * GET /api/integrations — the full 47-connector catalog merged with persisted
 * connection state. Provisions missing rows (disabled, empty config), backfills
 * name/category drift, redacts secrets and attaches per-connector stats.
 */
export async function GET() {
  const integrations = await provisionAndList();
  const body: IntegrationsResponse = { integrations };
  return NextResponse.json(body);
}
