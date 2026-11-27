import { NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { serializeFinding } from "@/lib/swarm/server/serialize";
import { buildPullRequestPayload } from "@/lib/swarm/remediation";

export const dynamic = "force-dynamic";

const PrSchema = z.object({
  language: z.string().trim().min(1).max(32).optional(),
});

const PatchPrSchema = z.object({
  prId: z.string().trim().min(1),
  status: z.enum(["opened", "merged", "closed"]),
});

type Ctx = { params: Promise<{ id: string }> };

export async function POST(req: Request, { params }: Ctx) {
  try {
    const { id } = await params;
    const json = await req.json().catch(() => ({}));
    const parsed = PrSchema.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid PR payload", details: parsed.error.issues },
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

    const vcsIntegrations = await db.integration.findMany({
      where: { key: { in: ["github", "gitlab"] }, enabled: true },
      select: { key: true, name: true },
    });
    const activeVcs = vcsIntegrations[0] ?? null;

    const serialized = serializeFinding(finding);
    const payload = buildPullRequestPayload(serialized, parsed.data.language);

    const pr = await db.remediationPr.create({
      data: {
        findingId: finding.id,
        scanId: finding.scanId,
        language: payload.language,
        branchName: payload.branchName,
        prTitle: payload.prTitle,
        prBody: payload.prBody,
        patchDiff: payload.patchDiff,
        status: "opened",
      },
    });

    await db.eventLog.create({
      data: {
        scanId: finding.scanId,
        type: "system",
        message: `Autonomous remediation PR staged on branch ${payload.branchName} (${payload.language})${
          activeVcs ? ` via ${activeVcs.name}` : ""
        } for "${finding.title}"`,
        meta: JSON.stringify({
          findingId: finding.id,
          prId: pr.id,
          branchName: payload.branchName,
          language: payload.language,
          vcsProvider: activeVcs?.key ?? null,
        }),
      },
    });

    return NextResponse.json({
      pr: {
        ...pr,
        createdAt: pr.createdAt.toISOString(),
      },
      integrationConnected: Boolean(activeVcs),
      vcsProvider: activeVcs?.name ?? null,
    });
  } catch (err) {
    console.error("Failed to create remediation PR:", err);
    return NextResponse.json(
      { error: "Internal server error creating remediation PR" },
      { status: 500 }
    );
  }
}

export async function PATCH(req: Request, { params }: Ctx) {
  try {
    const { id } = await params;
    const json = await req.json().catch(() => ({}));
    const parsed = PatchPrSchema.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid PR status payload", details: parsed.error.issues },
        { status: 400 }
      );
    }

    const existing = await db.remediationPr.findFirst({
      where: { id: parsed.data.prId, findingId: id },
      include: { finding: { select: { title: true } } },
    });

    if (!existing) {
      return NextResponse.json({ error: "Remediation PR not found" }, { status: 404 });
    }

    const updated = await db.remediationPr.update({
      where: { id: existing.id },
      data: { status: parsed.data.status },
    });

    await db.eventLog.create({
      data: {
        scanId: existing.scanId,
        type: "system",
        message: `Remediation PR ${existing.branchName} marked ${parsed.data.status} for "${existing.finding.title}"`,
        meta: JSON.stringify({
          findingId: id,
          prId: existing.id,
          status: parsed.data.status,
        }),
      },
    });

    return NextResponse.json({
      pr: {
        ...updated,
        createdAt: updated.createdAt.toISOString(),
      },
    });
  } catch (err) {
    console.error("Failed to update remediation PR:", err);
    return NextResponse.json(
      { error: "Internal server error updating remediation PR" },
      { status: 500 }
    );
  }
}
