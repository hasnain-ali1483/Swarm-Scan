import { NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

const RevokeSchema = z.object({
  provider: z.enum(["cloudflare", "awswaf", "modsecurity", "nginx"]),
});

type Ctx = { params: Promise<{ id: string }> };

export async function POST(req: Request, { params }: Ctx) {
  try {
    const { id } = await params;
    const json = await req.json().catch(() => ({}));
    const parsed = RevokeSchema.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid revoke payload", details: parsed.error.issues },
        { status: 400 }
      );
    }

    const existing = await db.virtualPatch.findUnique({
      where: {
        findingId_provider: {
          findingId: id,
          provider: parsed.data.provider,
        },
      },
      include: { finding: { select: { title: true } } },
    });

    if (!existing) {
      return NextResponse.json({ error: "Virtual patch not found" }, { status: 404 });
    }

    const now = new Date();
    const updated = await db.virtualPatch.update({
      where: { id: existing.id },
      data: {
        status: "revoked",
        revokedAt: now,
      },
    });

    await db.eventLog.create({
      data: {
        scanId: existing.scanId,
        type: "policy",
        message: `Virtual patch revoked (${parsed.data.provider}) for "${existing.finding.title}" on ${existing.endpoint}`,
        meta: JSON.stringify({
          findingId: id,
          provider: parsed.data.provider,
          ruleId: existing.ruleId,
        }),
      },
    });

    return NextResponse.json({
      patch: {
        ...updated,
        deployedAt: updated.deployedAt.toISOString(),
        revokedAt: updated.revokedAt ? updated.revokedAt.toISOString() : null,
        createdAt: updated.createdAt.toISOString(),
      },
    });
  } catch (err) {
    console.error("Failed to revoke virtual patch:", err);
    return NextResponse.json(
      { error: "Internal server error revoking virtual patch" },
      { status: 500 }
    );
  }
}
