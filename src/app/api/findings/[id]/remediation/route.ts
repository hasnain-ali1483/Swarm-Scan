import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { serializeFinding } from "@/lib/swarm/server/serialize";
import {
  generateRemediationPackage,
  type DeployedPatchItem,
  type FindingRemediationResponse,
  type RemediationPrItem,
} from "@/lib/swarm/remediation";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export async function GET(_req: Request, { params }: Ctx) {
  try {
    const { id } = await params;
    const finding = await db.finding.findUnique({
      where: { id },
      include: {
        evidence: { orderBy: { sequence: "asc" } },
        scan: { select: { id: true, target: true, status: true } },
        virtualPatches: { orderBy: { deployedAt: "desc" } },
        remediationPrs: { orderBy: { createdAt: "desc" } },
      },
    });

    if (!finding) {
      return NextResponse.json({ error: "Finding not found" }, { status: 404 });
    }

    const serialized = serializeFinding(finding);
    const pkg = generateRemediationPackage(serialized);

    const deployedPatches: DeployedPatchItem[] = finding.virtualPatches.map((vp) => ({
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
    }));

    const remediationPrs: RemediationPrItem[] = finding.remediationPrs.map((pr) => ({
      id: pr.id,
      findingId: pr.findingId,
      scanId: pr.scanId,
      language: pr.language,
      branchName: pr.branchName,
      prTitle: pr.prTitle,
      prBody: pr.prBody,
      patchDiff: pr.patchDiff,
      status: pr.status,
      createdAt: pr.createdAt.toISOString(),
    }));

    const response: FindingRemediationResponse = {
      package: pkg,
      deployedPatches,
      remediationPrs,
    };

    return NextResponse.json(response);
  } catch (err) {
    console.error("Failed to generate remediation package:", err);
    return NextResponse.json(
      { error: "Internal server error generating remediation" },
      { status: 500 }
    );
  }
}
