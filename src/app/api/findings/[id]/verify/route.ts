import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { chainHash } from "@/lib/swarm/server/hash";
import { serializeFinding } from "@/lib/swarm/server/serialize";
import { bayesianConfidence, bandOf } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

/**
 * Simulated independent re-verification: appends a `reverify` evidence entry
 * (LR 1.8) that CONTINUES the scan's WORM hash chain, then recomputes the
 * finding's Bayesian posterior confidence and band.
 */
export async function POST(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const finding = await db.finding.findUnique({
    where: { id },
    include: { scan: { select: { id: true, target: true, status: true } } },
  });
  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  const lastEntry = await db.evidence.findFirst({
    where: { scanId: finding.scanId },
    orderBy: { sequence: "desc" },
  });
  const prevHash = lastEntry?.hash ?? "0".repeat(64);
  const sequence = (lastEntry?.sequence ?? 0) + 1;

  const now = new Date();
  const content = JSON.stringify({
    reverify: true,
    technique: "independent_confirmation",
    operator: "auto-verifier",
    ts: now.toISOString(),
    result: "consistent",
  });

  await db.evidence.create({
    data: {
      findingId: finding.id,
      scanId: finding.scanId,
      kind: "reverify",
      lr: 1.8,
      content,
      hash: chainHash(prevHash, sequence, content),
      prevHash,
      sequence,
      createdAt: now,
    },
  });

  const likelihood = finding.likelihood * 1.8;
  const confidence = bayesianConfidence(finding.priorOdds, likelihood);

  const updated = await db.finding.update({
    where: { id: finding.id },
    data: { confidence, likelihood, band: bandOf(confidence) },
    include: {
      evidence: { orderBy: { sequence: "asc" } },
      scan: { select: { id: true, target: true, status: true } },
    },
  });

  await db.eventLog.create({
    data: {
      scanId: finding.scanId,
      type: "finding",
      message: `Re-verification passed — confidence ${confidence}`,
    },
  });

  return NextResponse.json(serializeFinding(updated));
}
