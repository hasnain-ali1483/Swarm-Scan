import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { serializeScopeRule } from "@/lib/swarm/server/serialize";
import { scopeRuleSchema } from "@/lib/swarm/server/validators";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export async function PUT(req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const existing = await db.scopeRule.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Scope rule not found" }, { status: 404 });
  }
  const raw = await req.json().catch(() => null);
  const parsed = scopeRuleSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid scope rule", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const { name, cidrs, mode, enforced } = parsed.data;
  const rule = await db.scopeRule.update({
    where: { id },
    data: { name, cidrs: JSON.stringify(cidrs), mode, enforced },
  });
  return NextResponse.json(serializeScopeRule(rule));
}

export async function DELETE(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const existing = await db.scopeRule.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Scope rule not found" }, { status: 404 });
  }
  await db.scopeRule.delete({ where: { id } });
  return NextResponse.json({ ok: true });
}
