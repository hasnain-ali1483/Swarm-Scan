import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { serializeTarget } from "@/lib/swarm/server/serialize";
import { kindOf, validateTargetValue } from "@/lib/swarm/server/scope";

export const dynamic = "force-dynamic";

const createTargetSchema = z.object({
  name: z.string().trim().min(1).max(120),
  value: z.string().trim().min(1).max(253),
  scope: z.enum(["internal", "external"]),
  environment: z.enum(["lab", "external"]).optional(),
  note: z.string().trim().max(500).optional(),
  // operator attestation: registering with authorized=true records the attestation
  authorized: z.boolean().optional(),
  attestedBy: z.string().trim().max(120).optional(),
});

export async function GET() {
  const targets = await db.target.findMany({ orderBy: { createdAt: "desc" } });
  return NextResponse.json(targets.map(serializeTarget));
}

export async function POST(req: NextRequest) {
  const raw = await req.json().catch(() => null);
  const parsed = createTargetSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid target", details: parsed.error.issues }, { status: 400 });
  }
  const { name, value, scope, environment, note, authorized, attestedBy } = parsed.data;

  const verdict = validateTargetValue(value, scope);
  if (!verdict.ok) {
    return NextResponse.json({ error: `Target rejected — ${verdict.reason}` }, { status: 400 });
  }

  const row = await db.target.create({
    data: {
      name,
      value,
      scope,
      environment: environment ?? "external",
      kind: kindOf(value),
      note: note ?? null,
      authorized: authorized === true,
      attestedBy: authorized === true ? attestedBy ?? "operator" : null,
      attestedAt: authorized === true ? new Date() : null,
    },
  });
  return NextResponse.json(serializeTarget(row), { status: 201 });
}
