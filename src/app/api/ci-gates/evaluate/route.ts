import { NextResponse } from "next/server";
import { evaluateCiGates } from "@/lib/swarm/server/ci-gates";
import type { CiEvaluateResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/** POST /api/ci-gates/evaluate — re-evaluate all gates from the latest benchmark run per agent. */
export async function POST() {
  try {
    const { gates, summary, evaluated, changed } = await evaluateCiGates();
    const body: CiEvaluateResponse = { gates, summary, evaluated, changed };
    return NextResponse.json(body);
  } catch (err) {
    console.error("[api/ci-gates/evaluate] POST failed", err);
    return NextResponse.json({ error: "CI gate evaluation failed" }, { status: 500 });
  }
}
