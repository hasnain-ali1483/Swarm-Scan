import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { integrationCatalogFor } from "@/lib/swarm/integrations-catalog";
import {
  aggregateIntegrationStats,
  logIntegrationEvent,
  mergeIntegrationItem,
  parseConfigJson,
  validateConfigValues,
} from "@/lib/swarm/server/integrations";

export const dynamic = "force-dynamic";

const updateIntegrationSchema = z.object({
  enabled: z.boolean().optional(),
  config: z.record(z.string(), z.string()).optional(),
});

type Ctx = { params: Promise<{ id: string }> };

/** Re-usable "merge stats + row" helper for the response body. */
async function itemForRow(id: string) {
  const row = await db.integration.findUnique({ where: { id } });
  if (!row) return null;
  const events = await db.eventLog.findMany({
    where: { type: "integration" },
    select: { meta: true },
  });
  return mergeIntegrationItem(row, aggregateIntegrationStats(events));
}

/**
 * PUT /api/integrations/:id — patch connection state (enable/disable, partial
 * config merge). Server-enforced rules:
 *   • unknown config keys are rejected (400)
 *   • secrets are write-only: an empty patch value keeps the stored secret
 *   • pinnedVersion guardrail rejects mutable refs (latest/main/…) on save
 *   • VERIFICATION GATE — enabling requires a COMPLETE required-field set and
 *     a PASSING connection test on the current config. Anything less → 409;
 *     the connector can never appear "connected" without verification.
 *   • CONFIG-CHANGE INVALIDATION — saving new values clears the stored
 *     verification and auto-disconnects a live connector until re-verified.
 * Responds with IntegrationUpdateResponse (the merged item is masked).
 */
export async function PUT(req: NextRequest, { params }: Ctx) {
  const { id } = await params;
  const row = await db.integration.findUnique({ where: { id } });
  if (!row) {
    return NextResponse.json({ error: "Integration not found" }, { status: 404 });
  }
  const entry = integrationCatalogFor(row.key);
  if (!entry) {
    return NextResponse.json({ error: "Integration not found" }, { status: 404 });
  }

  const raw = await req.json().catch(() => null);
  const parsed = updateIntegrationSchema.safeParse(raw);
  if (!parsed.success) {
    return NextResponse.json(
      { error: "Invalid integration update", details: parsed.error.issues },
      { status: 400 }
    );
  }
  const { enabled, config } = parsed.data;

  const stored = parseConfigJson(row.config);
  let mergedConfig = stored;
  let configChanged = false;
  let notice: string | undefined;
  let autoDisabled = false;

  if (config) {
    // Unknown field guard: catalog field specs OR already-stored keys only.
    for (const key of Object.keys(config)) {
      const known = entry.fields.some((f) => f.key === key) || key in stored;
      if (!known) {
        return NextResponse.json(
          { error: `Unknown field ${key} for ${entry.name}` },
          { status: 400 }
        );
      }
    }

    const merged: Record<string, string> = { ...stored };
    for (const [key, value] of Object.entries(config)) {
      const spec = entry.fields.find((f) => f.key === key);
      const isSecret = spec?.secret === true;
      // Secret-keep: an empty value never wipes an existing secret.
      if (isSecret && value === "" && (stored[key] ?? "") !== "") continue;
      merged[key] = value;
    }

    // Guardrail check on the MERGED config (pinned refs only — required-ness
    // and URL syntax belong to the test/dispatch/sync paths).
    const guardrailIssues = validateConfigValues(entry, merged, {}, {
      required: false,
      urls: false,
    });
    if (guardrailIssues.length > 0) {
      return NextResponse.json(
        { error: "Configuration rejected by guardrails", issues: guardrailIssues },
        { status: 400 }
      );
    }

    mergedConfig = merged;
    configChanged = true;
    // Config change ⇒ the previous verification no longer describes this
    // connector. Clear it and disconnect until re-verified.
    autoDisabled = row.enabled;
  }

  // ── Verification gate — evaluate BEFORE writing anything ──────────────────
  const effectiveEnabled = enabled !== undefined ? enabled : row.enabled;
  if (effectiveEnabled && !row.enabled) {
    // Only ENABLING is gated (a live row stays live unless config changed).
    const mergedForCheck = configChanged ? mergedConfig : stored;
    const requiredIssues = validateConfigValues(entry, {}, mergedForCheck, {
      pinned: false,
    });
    if (requiredIssues.length > 0) {
      return NextResponse.json(
        {
          error: `Cannot connect — configuration incomplete: ${requiredIssues.join("; ")}`,
        },
        { status: 409 }
      );
    }
    const testIsCurrent = !configChanged && row.lastTestOk === true;
    if (!testIsCurrent) {
      const because = row.lastTestOk === false
        ? "the last connection test failed"
        : "no connection test is on record for this configuration";
      return NextResponse.json(
        {
          error: `Cannot connect — ${because}. Run Test connection (or Verify & Connect) and try again.`,
        },
        { status: 409 }
      );
    }
  }

  await db.integration.update({
    where: { id },
    data: {
      ...(configChanged
        ? {
            config: JSON.stringify(mergedConfig),
            // Invalidate the stale verification + disconnect a live connector.
            ...(row.enabled ? { enabled: false } : {}),
            lastTestAt: null,
            lastTestOk: null,
            lastTestLatencyMs: null,
            lastTestDetail: null,
          }
        : { ...(enabled !== undefined ? { enabled } : {}) }),
    },
  });

  if (configChanged) {
    await logIntegrationEvent(row.key, "config", `Configuration saved — ${entry.name}`, {
      changedKeys: Object.keys(config ?? {}),
      ...(autoDisabled ? { autoDisconnected: true } : {}),
    });
    if (autoDisabled) {
      notice =
        "Configuration changed — the connector was disconnected until a passing test re-verifies it.";
      await logIntegrationEvent(
        row.key,
        "toggle",
        `Auto-disconnected — ${entry.name} config changed, re-verification required`,
        { enabled: false, auto: true, reason: "config-changed" }
      );
    }
  }

  if (enabled !== undefined && !configChanged) {
    await logIntegrationEvent(
      row.key,
      "toggle",
      `${entry.name} ${enabled ? "connected" : "disconnected"}${enabled ? " — verified" : ""}`,
      { enabled, ...(enabled ? { verified: true } : {}) }
    );
  }

  const item = await itemForRow(id);
  if (!item) {
    return NextResponse.json({ error: "Integration not found" }, { status: 404 });
  }
  return NextResponse.json({
    integration: item,
    ...(autoDisabled ? { autoDisabled: true, notice } : {}),
  });
}
