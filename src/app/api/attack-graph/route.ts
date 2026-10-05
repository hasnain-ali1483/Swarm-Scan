import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { serializeChain } from "@/lib/swarm/server/serialize";
import type { AttackGraphResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const scanId = req.nextUrl.searchParams.get("scanId");
  const chains = await db.attackChain.findMany({
    where: scanId ? { scanId } : undefined,
    orderBy: { severity: "asc" },
  });
  const body: AttackGraphResponse = { chains: chains.map(serializeChain) };
  return NextResponse.json(body);
}
