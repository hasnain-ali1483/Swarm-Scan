import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { serializeFinding } from "@/lib/swarm/server/serialize";
import { generateRemediationPackage } from "@/lib/swarm/remediation";

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
      },
    });

    if (!finding) {
      return NextResponse.json({ error: "Finding not found" }, { status: 404 });
    }

    const serialized = serializeFinding(finding);
    const remediation = generateRemediationPackage(serialized);

    return NextResponse.json(remediation);
  } catch (err) {
    console.error("Failed to generate remediation package:", err);
    return NextResponse.json(
      { error: "Internal server error generating remediation" },
      { status: 500 }
    );
  }
}
