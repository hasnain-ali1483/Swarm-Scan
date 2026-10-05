import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { serializeChain } from "@/lib/swarm/server/serialize";
import type { ChainStep } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

/**
 * Advances an attack chain one step through its approval gate:
 * pending → approved → executed (simulated), bumping currentStep; when all
 * steps have executed the chain flips to verified.
 */
export async function POST(_req: Request, { params }: Ctx) {
  const { id } = await params;
  const chain = await db.attackChain.findUnique({ where: { id } });
  if (!chain) {
    return NextResponse.json({ error: "Attack chain not found" }, { status: 404 });
  }

  let steps: ChainStep[] = [];
  try {
    steps = JSON.parse(chain.steps) as ChainStep[];
  } catch {
    steps = [];
  }

  let currentStep = chain.currentStep;
  let verified = chain.verified;
  let advanced: ChainStep | null = null;

  if (currentStep < steps.length) {
    const step = steps[currentStep];
    if (step.status === "pending") {
      // approval gate passes, then the simulated execution completes
      step.status = "executed";
      advanced = step;
      currentStep += 1;
      if (currentStep >= steps.length) verified = true;
    }
  }

  if (advanced) {
    await db.attackChain.update({
      where: { id },
      data: {
        currentStep,
        verified,
        steps: JSON.stringify(steps),
      },
    });
    await db.eventLog.create({
      data: {
        scanId: chain.scanId,
        type: "chain",
        message: `Chain step verified: ${advanced.title}`,
      },
    });
  }

  const updated = await db.attackChain.findUniqueOrThrow({ where: { id } });
  return NextResponse.json({ chain: serializeChain(updated) });
}
