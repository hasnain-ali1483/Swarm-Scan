import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { serializeFinding } from "@/lib/swarm/server/serialize";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export async function GET(_req: Request, { params }: Ctx) {
  const { id } = await params;
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
  return NextResponse.json(serializeFinding(finding));
}
