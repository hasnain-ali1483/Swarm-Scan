import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import type { DeployedPatchItem } from "@/lib/swarm/remediation";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const sp = req.nextUrl.searchParams;
    const status = sp.get("status");
    const provider = sp.get("provider");
    const scanId = sp.get("scanId");

    const where: Record<string, string> = {};
    if (status) where.status = status;
    if (provider) where.provider = provider;
    if (scanId) where.scanId = scanId;

    const rows = await db.virtualPatch.findMany({
      where,
      orderBy: { deployedAt: "desc" },
      include: {
        finding: {
          select: { title: true, severity: true, target: true },
        },
      },
    });

    const patches: DeployedPatchItem[] = rows.map((vp) => ({
      id: vp.id,
      findingId: vp.findingId,
      scanId: vp.scanId,
      provider: vp.provider,
      ruleId: vp.ruleId,
      status: vp.status,
      ruleContent: vp.ruleContent,
      endpoint: vp.endpoint,
      deployedBy: vp.deployedBy,
      deployedAt: vp.deployedAt.toISOString(),
      revokedAt: vp.revokedAt ? vp.revokedAt.toISOString() : null,
      findingTitle: vp.finding.title,
      findingSeverity: vp.finding.severity,
      findingTarget: vp.finding.target,
    }));

    return NextResponse.json({
      patches,
      summary: {
        total: patches.length,
        deployed: patches.filter((p) => p.status === "deployed").length,
        revoked: patches.filter((p) => p.status === "revoked").length,
      },
    });
  } catch (err) {
    console.error("Failed to list virtual patches:", err);
    return NextResponse.json(
      { error: "Internal server error listing virtual patches" },
      { status: 500 }
    );
  }
}
