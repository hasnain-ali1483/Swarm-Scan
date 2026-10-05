import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { dispatchToIntegration } from "@/lib/swarm/server/integrations";

export const dynamic = "force-dynamic";

const dispatchSchema = z.object({
  approve: z.boolean().optional(),
  limit: z.coerce.number().int().min(1).max(25).optional(),
  minSeverity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
});

type Ctx = { params: Promise<{ id: string }> };

/**
 * POST /api/integrations/:id/dispatch — push confirmed findings to an outbound
 * connector. Every guardrail is enforced server-side in order: direction,
 * enabled, required config, SOAR approval, rate limit, severity filter, scope
 * firewall, evidence-key dedupe — then refs are allocated and audited.
 */
export async function POST(req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const raw = await req.json().catch(() => ({}));
  const parsed = dispatchSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid dispatch payload", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const { status, body } = await dispatchToIntegration(id, parsed.data);
  return NextResponse.json(body, { status });
}
