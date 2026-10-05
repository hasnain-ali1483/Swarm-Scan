import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { AGENTS_CATALOG, STATIC_AGENT_KEYS } from "@/lib/swarm/agents-catalog";
import { ENGINE_UNREACHABLE, engineFetch } from "@/lib/swarm/server/engine";
import { randomSeed } from "@/lib/swarm/server/hash";
import { serializeScan } from "@/lib/swarm/server/serialize";
import { validateTargetValue } from "@/lib/swarm/server/scope";
import { canAuthorizeDestructive } from "@/lib/swarm/access-roles";

export const dynamic = "force-dynamic";

const AGENT_KEYS = AGENTS_CATALOG.map((a) => a.key) as [string, ...string[]];
const STATIC_AGENT_SET = new Set(STATIC_AGENT_KEYS);
const ROLE_ENUM = ["owner", "admin", "operator", "auditor", "viewer"] as const;

// A scan is launched against a REGISTERED, AUTHORIZED target (prerequisite).
const createScanSchema = z.object({
  targetId: z.string().trim().min(1, "a registered target is required"),
  profile: z.enum(["quick", "full", "continuous"]),
  policyTier: z.enum(["safe", "standard", "aggressive"]),
  seed: z.string().max(64).optional(),
  agents: z.array(z.enum(AGENT_KEYS)).optional(),
  // The acting principal's role (from the authenticated session; the demo passes
  // the simulated role). Required to authorize the destructive-oracle tier.
  actingRole: z.enum(ROLE_ENUM).optional(),
});

export async function GET() {
  const scans = await db.scan.findMany({
    orderBy: { createdAt: "desc" },
    take: 50,
  });
  const groups = await db.finding.groupBy({
    by: ["scanId", "severity"],
    _count: { _all: true },
  });

  const perScan = new Map<string, { count: number; bySeverity: Record<string, number> }>();
  for (const g of groups) {
    const entry = perScan.get(g.scanId) ?? { count: 0, bySeverity: {} };
    entry.count += g._count._all;
    entry.bySeverity[g.severity] = (entry.bySeverity[g.severity] ?? 0) + g._count._all;
    perScan.set(g.scanId, entry);
  }

  return NextResponse.json(
    scans.map((scan) => {
      const agg = perScan.get(scan.id);
      return serializeScan({
        ...scan,
        findingsCount: agg?.count ?? 0,
        findingsBySeverity: agg?.bySeverity ?? {},
      });
    })
  );
}

export async function POST(req: NextRequest) {
  const raw = await req.json().catch(() => null);
  const parsed = createScanSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid scan request", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const { targetId, profile, policyTier, seed, agents, actingRole } = parsed.data;

  // ── Destructive-oracle gate (OWNER-EXCLUSIVE) ──
  // The aggressive tier is the destructive/intrusive class (data-touching, RCE,
  // exfil). Only an Owner may authorize it — not even Admin.
  if (policyTier === "aggressive" && !canAuthorizeDestructive(actingRole ?? "viewer")) {
    return NextResponse.json(
      {
        error:
          "Destructive-oracle class (aggressive tier) requires the Owner role — not even Admin can authorize data-touching / RCE / exfil probes.",
      },
      { status: 403 }
    );
  }

  // ── Prerequisite + authorization wall ──
  const target = await db.target.findUnique({ where: { id: targetId } });
  if (!target) {
    return NextResponse.json({ error: "Target not found — register it under Targets first" }, { status: 404 });
  }
  if (!target.authorized) {
    return NextResponse.json(
      { error: "Target is not authorized — attest authorization under Targets before scanning" },
      { status: 403 }
    );
  }
  const scope = target.scope as "internal" | "external";
  const verdict = validateTargetValue(target.value, scope);
  if (!verdict.ok) {
    return NextResponse.json({ error: `Target rejected — ${verdict.reason}` }, { status: 400 });
  }

  // Active proof-of-exploit (aggressive tier) is LAB-ONLY. A real/external target
  // (e.g. a bug-bounty asset authorized for "scanning only") is never actively
  // exploited — it stays detection-only regardless of role.
  if (policyTier === "aggressive" && target.environment !== "lab") {
    return NextResponse.json(
      {
        error:
          "Active exploitation (aggressive tier) is permitted only on LAB targets you own. External targets are scanning/detection-only — register a lab target or use the standard tier.",
      },
      { status: 403 }
    );
  }

  // Dynamic agents are never plannable — strip them from an explicit selection
  // (they spawn at runtime when their trigger fires).
  const effectiveAgents = agents?.filter((k) => STATIC_AGENT_SET.has(k));

  const row = await db.scan.create({
    data: {
      target: target.value,
      scope,
      targetId: target.id,
      profile,
      policyTier,
      seed: seed && seed.length > 0 ? seed : randomSeed(),
      status: "running",
      startedAt: new Date(),
      agentCount:
        effectiveAgents && effectiveAgents.length > 0
          ? effectiveAgents.length
          : profile === "quick"
            ? 6
            : STATIC_AGENT_KEYS.length,
    },
  });

  try {
    await engineFetch("/start", {
      method: "POST",
      body: JSON.stringify({
        scanId: row.id,
        target: target.value,
        scope,
        environment: target.environment, // lab | external — engine gates active exploit to lab
        authorized: true, // enforced above — engine re-validates
        destructive: policyTier === "aggressive", // owner-gated above; engine re-checks
        profile,
        policyTier,
        seed: row.seed,
        ...(effectiveAgents && effectiveAgents.length > 0 ? { agents: effectiveAgents } : {}),
      }),
    });
  } catch (err) {
    await db.scan.delete({ where: { id: row.id } }).catch(() => undefined);
    const message = err instanceof Error ? err.message : ENGINE_UNREACHABLE;
    return NextResponse.json({ error: message }, { status: 502 });
  }

  await db.eventLog.create({
    data: {
      scanId: row.id,
      type: "system",
      message: `Scan plan created for ${target.value} (${scope} engagement, profile: ${profile}, tier: ${policyTier})`,
    },
  });

  return NextResponse.json(serializeScan(row), { status: 201 });
}
