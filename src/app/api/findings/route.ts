import { NextResponse, type NextRequest } from "next/server";
import type { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
import { serializeFinding } from "@/lib/swarm/server/serialize";
import type { FindingsListResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const BANDS = new Set(["suspected", "likely", "confirmed"]);

export async function GET(req: NextRequest) {
  const sp = req.nextUrl.searchParams;

  const severity = (sp.get("severity") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => SEVERITIES.has(s));
  const band = sp.get("band");
  const agentKey = sp.get("agentKey");
  const scanId = sp.get("scanId");
  const q = sp.get("q")?.trim();
  const page = Math.max(1, Number.parseInt(sp.get("page") ?? "1", 10) || 1);
  const pageSize = Math.min(
    100,
    Math.max(1, Number.parseInt(sp.get("pageSize") ?? "20", 10) || 20)
  );

  const where: Prisma.FindingWhereInput = {
    ...(severity.length > 0 ? { severity: { in: severity } } : {}),
    ...(band && BANDS.has(band) ? { band } : {}),
    ...(agentKey ? { agentKey } : {}),
    ...(scanId ? { scanId } : {}),
    ...(q
      ? {
          OR: [
            { title: { contains: q } },
            { target: { contains: q } },
            { endpoint: { contains: q } },
          ],
        }
      : {}),
  };

  const [total, findings] = await Promise.all([
    db.finding.count({ where }),
    db.finding.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: {
        evidence: { orderBy: { sequence: "asc" } },
        scan: { select: { id: true, target: true, status: true } },
      },
    }),
  ]);

  const body: FindingsListResponse = {
    findings: findings.map(serializeFinding),
    total,
    page,
    pageSize,
  };
  return NextResponse.json(body);
}
