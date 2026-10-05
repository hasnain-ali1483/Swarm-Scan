import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import {
  AGENT_RUN_STATUS_ENUM,
  BAND_ENUM,
  EVIDENCE_KIND_ENUM,
  SEVERITY_ENUM,
} from "@/lib/swarm/server/validators";

export const dynamic = "force-dynamic";

/**
 * Engine → control-plane ingest callback. Idempotent: re-ingesting the same
 * scan replaces its agent runs, findings (+evidence), chains and events while
 * keeping the WORM evidence hashes/sequences exactly as the engine signed them.
 */
const ingestSchema = z.object({
  scanId: z.string().min(1),
  status: z.enum(["completed", "killed", "failed"]),
  requestCount: z.number().int().min(0),
  agentRuns: z.array(
    z.object({
      agentKey: z.string(),
      agentName: z.string(),
      version: z.string(),
      state: z.string(),
      status: z.enum(AGENT_RUN_STATUS_ENUM),
      progress: z.number(),
      requests: z.number(),
      findings: z.number(),
    })
  ),
  findings: z.array(
    z.object({
      agentKey: z.string(),
      title: z.string(),
      severity: z.enum(SEVERITY_ENUM),
      category: z.string(),
      confidence: z.number(),
      band: z.enum(BAND_ENUM),
      target: z.string(),
      endpoint: z.string().nullable(),
      cve: z.string().nullable(),
      description: z.string(),
      pocScript: z.string().nullable(),
      priorOdds: z.number(),
      likelihood: z.number(),
      createdAt: z.string(),
      evidence: z.array(
        z.object({
          kind: z.enum(EVIDENCE_KIND_ENUM),
          lr: z.number(),
          content: z.string(),
          hash: z.string(),
          prevHash: z.string(),
          sequence: z.number().int(),
        })
      ),
    })
  ),
  events: z.array(
    z.object({
      type: z.string(),
      message: z.string(),
      meta: z.string().nullable().optional(),
    })
  ),
  chains: z
    .array(
      z.object({
        name: z.string(),
        severity: z.enum(SEVERITY_ENUM),
        steps: z.array(
          z.object({
            title: z.string(),
            action: z.string(),
            status: z.enum(["pending", "approved", "executed", "failed"]),
            findingId: z.string().nullable().optional(),
          })
        ),
        graph: z.object({
          nodes: z.array(
            z.object({
              id: z.string(),
              label: z.string(),
              type: z.string(),
              severity: z.string().optional(),
              detail: z.string().optional(),
              x: z.number().optional(),
              y: z.number().optional(),
            })
          ),
          edges: z.array(z.object({ from: z.string(), to: z.string(), label: z.string() })),
        }),
      })
    )
    .optional(),
});

function parseDate(value: string): Date {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? new Date() : d;
}

export async function POST(req: NextRequest) {
  const raw = await req.json().catch(() => null);
  const parsed = ingestSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid ingest payload", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const payload = parsed.data;

  const scan = await db.scan.findUnique({ where: { id: payload.scanId } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const now = new Date();
  const startedAt = scan.startedAt ?? now;

  // 1. scan terminal state (killed handled identically — evidence preserved)
  await db.scan.update({
    where: { id: scan.id },
    data: {
      status: payload.status,
      completedAt: now,
      progress: 100,
      requestCount: payload.requestCount,
    },
  });

  // 2. replace agent runs with the engine's final states
  await db.agentRun.deleteMany({ where: { scanId: scan.id } });
  if (payload.agentRuns.length > 0) {
    await db.agentRun.createMany({
      data: payload.agentRuns.map((a) => ({
        scanId: scan.id,
        agentKey: a.agentKey,
        agentName: a.agentName,
        version: a.version,
        state: a.state,
        status: a.status,
        progress: a.progress,
        requests: a.requests,
        findings: a.findings,
        startedAt,
        endedAt: now,
        createdAt: now,
      })),
    });
  }

  // 3. replace findings + evidence (hashes/sequences kept as signed by the engine)
  await db.finding.deleteMany({ where: { scanId: scan.id } }); // cascades evidence
  for (const f of payload.findings) {
    await db.finding.create({
      data: {
        scanId: scan.id,
        agentKey: f.agentKey,
        title: f.title,
        severity: f.severity,
        category: f.category,
        confidence: f.confidence,
        band: f.band,
        target: f.target,
        endpoint: f.endpoint,
        cve: f.cve,
        description: f.description,
        pocScript: f.pocScript,
        priorOdds: f.priorOdds,
        likelihood: f.likelihood,
        createdAt: parseDate(f.createdAt),
        evidence: {
          create: f.evidence.map((e) => ({
            scanId: scan.id,
            kind: e.kind,
            lr: e.lr,
            content: e.content,
            hash: e.hash,
            prevHash: e.prevHash,
            sequence: e.sequence,
            createdAt: now,
          })),
        },
      },
    });
  }

  // 4. events from the engine run (capped)
  const events = payload.events.slice(0, 120);
  if (events.length > 0) {
    await db.eventLog.createMany({
      data: events.map((e) => ({
        scanId: scan.id,
        type: e.type,
        message: e.message,
        meta: e.meta ?? null,
        createdAt: now,
      })),
    });
  }

  // 5. correlator chains
  await db.attackChain.deleteMany({ where: { scanId: scan.id } });
  for (const c of payload.chains ?? []) {
    await db.attackChain.create({
      data: {
        scanId: scan.id,
        name: c.name,
        severity: c.severity,
        verified: false,
        currentStep: 0,
        steps: JSON.stringify(c.steps),
        graph: JSON.stringify(c.graph),
      },
    });
  }

  return NextResponse.json({ ok: true, scanId: scan.id });
}
