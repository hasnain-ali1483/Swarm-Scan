import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { chainHash, ZERO_HASH } from "@/lib/swarm/server/hash";
import type { LedgerVerifyResponse } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/**
 * Walks every per-scan WORM chain and verifies:
 *   1. hash integrity  — hash === sha256(`${prevHash}:${sequence}:${content}`)
 *   2. linkage         — entry N's prevHash === entry N-1's hash
 *                        (first entry of each scan must reference 64 zeros)
 */
export async function GET() {
  const scans = await db.scan.findMany({
    orderBy: { createdAt: "asc" },
    select: { id: true },
  });

  let checked = 0;
  let brokenAt: number | null = null;
  let headHash = ZERO_HASH;

  for (const scan of scans) {
    const entries = await db.evidence.findMany({
      where: { scanId: scan.id },
      orderBy: { sequence: "asc" },
    });
    let prevHash = ZERO_HASH;
    for (const entry of entries) {
      checked += 1;
      const expected = chainHash(entry.prevHash, entry.sequence, entry.content);
      if (entry.prevHash !== prevHash || entry.hash !== expected) {
        if (brokenAt === null) brokenAt = checked;
      }
      prevHash = entry.hash;
    }
    if (entries.length > 0) {
      headHash = entries[entries.length - 1].hash;
    }
  }

  const body: LedgerVerifyResponse = {
    valid: brokenAt === null,
    checked,
    brokenAt,
    headHash,
    checkedAt: new Date().toISOString(),
  };
  return NextResponse.json(body);
}
