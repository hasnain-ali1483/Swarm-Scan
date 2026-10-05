import { NextResponse, type NextRequest } from "next/server";

import { db } from "@/lib/db";
import { buildExportBundle, exportFileName } from "@/lib/swarm/server/compliance";
import type { ComplianceExportResponse, ComplianceExportOptions } from "@/lib/swarm/types";

export const dynamic = "force-dynamic";

/**
 * POST /api/compliance/export — seals a point-in-time evidence bundle and
 * records the delivery in the EventLog audit trail (type "compliance"). The
 * response carries the manifest metadata; the client saves the JSON receipt.
 */
export async function POST(req: NextRequest) {
  try {
    const raw = (await req.json().catch(() => null)) as
      | { includeRawEvidence?: unknown; includeSarif?: unknown; anonymize?: unknown }
      | null;

    const options: ComplianceExportOptions = {
      includeRawEvidence: raw?.includeRawEvidence === true,
      includeSarif: raw?.includeSarif === true,
      anonymize: raw?.anonymize === true,
    };

    const bundle = await buildExportBundle(options);
    const fileName = exportFileName(bundle.manifest);
    const controls = bundle.manifest.find((s) => s.section === "controls")?.entries ?? 0;
    const evidenceEntries = bundle.manifest.find((s) => s.section === "evidence")?.entries ?? 0;

    await db.eventLog.create({
      data: {
        type: "compliance",
        message: `SOC 2 export pack generated — ${evidenceEntries} evidence entries · ${controls} controls · manifest sealed (${bundle.manifest.length} sections)`,
        meta: JSON.stringify({ options, fileName, sizeBytes: bundle.sizeBytes }),
      },
    });

    const body: ComplianceExportResponse = {
      ok: true,
      fileName,
      sizeBytes: bundle.sizeBytes,
      entries: bundle.entries,
      controls,
      downloadedAt: new Date().toISOString(),
      manifest: bundle.manifest,
    };
    return NextResponse.json(body);
  } catch (err) {
    console.error("[api/compliance/export] POST failed", err);
    return NextResponse.json({ error: "Failed to seal export pack" }, { status: 500 });
  }
}
