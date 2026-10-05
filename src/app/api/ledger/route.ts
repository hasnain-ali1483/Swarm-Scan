import { NextResponse, type NextRequest } from "next/server";
import { db } from "@/lib/db";
import { serializeEvidence } from "@/lib/swarm/server/serialize";
import type { LedgerResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const sp = req.nextUrl.searchParams;
  const scanId = sp.get("scanId") ?? undefined;
  const limit = Math.min(500, Math.max(1, Number.parseInt(sp.get("limit") ?? "150", 10) || 150));
  const offset = Math.max(0, Number.parseInt(sp.get("offset") ?? "0", 10) || 0);

  const where = scanId ? { scanId } : {};

  const [total, entries] = await Promise.all([
    db.evidence.count({ where }),
    db.evidence.findMany({
      where,
      orderBy: [{ scan: { createdAt: "asc" } }, { sequence: "asc" }],
      skip: offset,
      take: limit,
      include: {
        finding: { select: { title: true } },
        scan: { select: { target: true } },
      },
    }),
  ]);

  const body: LedgerResponse = {
    entries: entries.map((e) => ({
      ...serializeEvidence(e),
      findingTitle: e.finding?.title ?? null,
      scanTarget: e.scan?.target ?? "",
    })),
    total,
  };
  return NextResponse.json(body);
}
