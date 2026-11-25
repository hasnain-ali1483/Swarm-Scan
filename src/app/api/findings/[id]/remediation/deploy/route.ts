import { NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { serializeFinding } from "@/lib/swarm/server/serialize";
import { generateRemediationPackage } from "@/lib/swarm/remediation";

export const dynamic = "force-dynamic";

const DeploySchema = z.object({
  provider: z.enum(["cloudflare", "awswaf", "modsecurity", "nginx"]),
  deployedBy: z.string().trim().min(1).max(64).optional(),
});

type Ctx = { params: Promise<{ id: string }> };

export async function POST(req: Request, { params }: Ctx) {
  try {
    const { id } = await params;
    const json = await req.json().catch(() => ({}));
    const parsed = DeploySchema.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid deploy payload", details: parsed.error.issues },
        { status: 400 }
      );
    }

    const finding = await db.finding.findUnique({
      where: { id },
      include: {
        evidence: { orderBy: { sequence: "asc" } },
        scan: { select: { id: true, target: true, status: true } },
      },
    });
    if (!finding) {
      return NextResponse.json({ error: "Finding not found" }, { status: 404 });
    }

    const serialized = serializeFinding(finding);
    const pkg = generateRemediationPackage(serialized);
    const rule = pkg.wafRules.find((r) => r.provider === parsed.data.provider);
    if (!rule) {
      return NextResponse.json(
        { error: `No WAF rule available for provider ${parsed.data.provider}` },
        { status: 400 }
      );
    }

    const now = new Date();
    const deployedBy = parsed.data.deployedBy ?? "operator";
    const ruleId = rule.filename.replace(/\.[^.]+$/, "");

    const patch = await db.virtualPatch.upsert({
      where: {
        findingId_provider: {
          findingId: finding.id,
          provider: parsed.data.provider,
        },
      },
      update: {
        status: "deployed",
        ruleContent: rule.code,
        ruleId,
        endpoint: pkg.endpoint,
        deployedBy,
        deployedAt: now,
        revokedAt: null,
      },
      create: {
        findingId: finding.id,
        scanId: finding.scanId,
        provider: parsed.data.provider,
        ruleId,
        status: "deployed",
        ruleContent: rule.code,
        endpoint: pkg.endpoint,
        deployedBy,
        deployedAt: now,
      },
    });

    await db.eventLog.create({
      data: {
        scanId: finding.scanId,
        type: "policy",
        message: `Virtual patch deployed (${rule.providerLabel}) for "${finding.title}" on ${pkg.endpoint}`,
        meta: JSON.stringify({
          findingId: finding.id,
          provider: parsed.data.provider,
          ruleId,
          deployedBy,
        }),
      },
    });

    return NextResponse.json({
      patch: {
        ...patch,
        deployedAt: patch.deployedAt.toISOString(),
        revokedAt: patch.revokedAt ? patch.revokedAt.toISOString() : null,
        createdAt: patch.createdAt.toISOString(),
      },
    });
  } catch (err) {
    console.error("Failed to deploy virtual patch:", err);
    return NextResponse.json(
      { error: "Internal server error deploying virtual patch" },
      { status: 500 }
    );
  }
}
