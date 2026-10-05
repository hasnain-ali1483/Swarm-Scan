import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { connectIntegration } from "@/lib/swarm/server/integrations";

export const dynamic = "force-dynamic";

const connectSchema = z.object({
  /** optional config patch — persisted (secret-keep, guardrail-checked) before testing */
  config: z.record(z.string(), z.string()).optional(),
});

type Ctx = { params: Promise<{ id: string }> };

/**
 * POST /api/integrations/:id/connect — the guided verify-and-connect flow.
 * Persists the optional config patch, runs the connection test against the
 * STORED config, and enables the connector ONLY when the test passed.
 * The response carries the test result plus the merged item, so the dialog
 * renders one coherent outcome (issues list when verification failed).
 */
export async function POST(req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const raw = await req.json().catch(() => null);
  const parsed = connectSchema.safeParse(raw ?? {});
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid connect payload", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const outcome = await connectIntegration(id, parsed.data.config);
  return NextResponse.json(outcome.body, { status: outcome.status });
}
