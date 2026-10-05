import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { serializePolicy } from "@/lib/swarm/server/serialize";

export const dynamic = "force-dynamic";

const updatePolicySchema = z.object({
  code: z.string().min(1).optional(),
  enabled: z.boolean().optional(),
});

type Ctx = { params: Promise<{ id: string }> };

export async function PUT(req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const existing = await db.policy.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Policy not found" }, { status: 404 });
  }

  const raw = await req.json().catch(() => null);
  const parsed = updatePolicySchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid policy update", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const { code, enabled } = parsed.data;

  const policy = await db.policy.update({
    where: { id },
    data: {
      ...(code !== undefined ? { code } : {}),
      ...(enabled !== undefined ? { enabled } : {}),
    },
  });

  if (enabled !== undefined && enabled !== existing.enabled) {
    await db.eventLog.create({
      data: {
        type: "policy",
        message: `Policy "${policy.name}" ${enabled ? "enabled" : "disabled"}`,
      },
    });
  }
  return NextResponse.json(serializePolicy(policy));
}

export async function DELETE(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const existing = await db.policy.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Policy not found" }, { status: 404 });
  }
  await db.policy.delete({ where: { id } });
  return NextResponse.json({ ok: true });
}
