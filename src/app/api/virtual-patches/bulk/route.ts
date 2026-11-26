import { NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { serializeFinding } from "@/lib/swarm/server/serialize";
import { generateRemediationPackage } from "@/lib/swarm/remediation";

export const dynamic = "force-dynamic";

const BulkDeploySchema = z.object({
  scanId: z.string().trim().min(1),
  provider: z.enum(["cloudflare", "awswaf", "modsecurity", "nginx"]),
  scope: z.enum(["all", "high_critical", "confirmed"]).default("all"),
  deployedBy: z.string().trim().min(1).max(64).optional(),
});

const PROVIDER_INTEGRATION_KEY: Record<string, string> = {
  cloudflare: "cloudflare-waf",
  awswaf: "aws-waf",
};

export async function POST(req: Request) {
  try {
    const json = await req.json().catch(() => ({}));
    const parsed = BulkDeploySchema.safeParse(json);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid bulk deploy payload", details: parsed.error.issues },
        { status: 400 }
      );
    }

    const { scanId, provider, scope } = parsed.data;
    const deployedBy = parsed.data.deployedBy ?? "operator";

    const scan = await db.scan.findUnique({
      where: { id: scanId },
      include: {
        findings: {
          include: {
            evidence: { orderBy: { sequence: "asc" } },
          },
        },
      },
    });

    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const targetFindings = scan.findings.filter((f) => {
      if (scope === "high_critical") return f.severity === "critical" || f.severity === "high";
      if (scope === "confirmed") return f.band === "confirmed";
      return true;
    });

    if (targetFindings.length === 0) {
      return NextResponse.json({
        deployedCount: 0,
        provider,
        scope,
        integrationConnected: false,
        patches: [],
      });
    }

    // Check if an outbound WAF integration is connected for this provider
    const integrationKey = PROVIDER_INTEGRATION_KEY[provider];
    const integration = integrationKey
      ? await db.integration.findUnique({ where: { key: integrationKey } })
      : null;
    const integrationConnected = Boolean(integration?.enabled);

    const now = new Date();
    const results = [];

    for (const f of targetFindings) {
      const serialized = serializeFinding({
        ...f,
        scan: { id: scan.id, target: scan.target, status: scan.status },
      });
      const pkg = generateRemediationPackage(serialized);
      const rule = pkg.wafRules.find((r) => r.provider === provider);
      if (!rule) continue;

      const ruleId = rule.filename.replace(/\.[^.]+$/, "");
      const patch = await db.virtualPatch.upsert({
        where: {
          findingId_provider: {
            findingId: f.id,
            provider,
          },
        },
        update: {
          status: "deployed",
          ruleContent: rule.code,
          ruleId,
          endpoint: pkg.endpoint,
          deployedBy,
          deployedAt: now,
          revokedAt: null,
        },
        create: {
          findingId: f.id,
          scanId: scan.id,
          provider,
          ruleId,
          status: "deployed",
          ruleContent: rule.code,
          endpoint: pkg.endpoint,
          deployedBy,
          deployedAt: now,
        },
      });
      results.push({
        ...patch,
        deployedAt: patch.deployedAt.toISOString(),
        revokedAt: patch.revokedAt ? patch.revokedAt.toISOString() : null,
        createdAt: patch.createdAt.toISOString(),
      });
    }

    await db.eventLog.create({
      data: {
        scanId: scan.id,
        type: "policy",
        message: `Bulk virtual patch deployed: ${results.length} ${provider} rules active for ${scan.target} (scope: ${scope})`,
        meta: JSON.stringify({
          provider,
          scope,
          deployedCount: results.length,
          integrationConnected,
          deployedBy,
        }),
      },
    });

    return NextResponse.json({
      deployedCount: results.length,
      provider,
      scope,
      integrationConnected,
      patches: results,
    });
  } catch (err) {
    console.error("Bulk virtual patch deploy failed:", err);
    return NextResponse.json(
      { error: "Internal server error deploying bulk virtual patches" },
      { status: 500 }
    );
  }
}
