import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { serializeTarget } from "@/lib/swarm/server/serialize";
import { validateTargetValue } from "@/lib/swarm/server/scope";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

const patchSchema = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  note: z.string().trim().max(500).optional(),
  // attestation toggle — authorizing requires an attester name
  authorized: z.boolean().optional(),
  attestedBy: z.string().trim().max(120).optional(),
});

export async function GET(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const t = await db.target.findUnique({ where: { id } });
  if (!t) return NextResponse.json({ error: "Target not found" }, { status: 404 });
  return NextResponse.json(serializeTarget(t));
}

export async function PATCH(req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const existing = await db.target.findUnique({ where: { id } });
  if (!existing) return NextResponse.json({ error: "Target not found" }, { status: 404 });

  const raw = await req.json().catch(() => null);
  const parsed = patchSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid patch", details: parsed.error.issues }, { status: 400 });
  }
  const { name, note, authorized, attestedBy } = parsed.data;

  // Re-validate scope on (re-)authorization — never authorize an out-of-scope value.
  if (authorized === true) {
    const verdict = validateTargetValue(existing.value, existing.scope as "internal" | "external");
    if (!verdict.ok) {
      return NextResponse.json({ error: `Cannot authorize — ${verdict.reason}` }, { status: 400 });
    }
  }

  const row = await db.target.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(note !== undefined ? { note } : {}),
      ...(authorized !== undefined
        ? authorized
          ? { authorized: true, attestedBy: attestedBy ?? "operator", attestedAt: new Date() }
          : { authorized: false, attestedBy: null, attestedAt: null }
        : {}),
    },
  });
  return NextResponse.json(serializeTarget(row));
}

export async function DELETE(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const existing = await db.target.findUnique({ where: { id } });
  if (!existing) return NextResponse.json({ error: "Target not found" }, { status: 404 });
  await db.target.delete({ where: { id } });
  return NextResponse.json({ ok: true });
}
