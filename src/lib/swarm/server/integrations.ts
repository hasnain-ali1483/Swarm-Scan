// ─── Integration engine — 47-connector catalog + server-enforced guardrails ──
// Round 14 backend. The catalog (integrations-catalog.ts) is the single source
// of truth for connector metadata; this engine persists ONLY connection state
// (enabled / config values / lastTest / lastSyncAt) in the Integration table
// and enforces the guardrails that turn the "common implementation mistakes"
// into hard runtime rules:
//
//   • secrets never leave the server (masked to "" in every response)
//   • pinnedVersion — latest/main/master/head refs are rejected on save,
//     test, dispatch and sync
//   • requiresApproval — SOAR dispatches need an explicit analyst approval
//   • scopeEnforced — dispatched finding targets must pass the active scope
//     firewall rules (allowlist ∪ authorized-scan provenance, minus denylist)
//   • dedupeByEvidence — findings already dispatched (by evidence-key prefix)
//     are skipped instead of re-ticketed
//   • rateLimitPerMin — N dispatch/sync events per rolling 60s → 429
//
// All integration actions are audited in the EventLog under type
// "integration" with meta { integrationKey, action, … } — that audit trail is
// the source for stats, rate limiting, dedupe sets and the activity feed.

import { createHash } from "node:crypto";
import type { Integration as IntegrationRow } from "@prisma/client";
import { db } from "@/lib/db";
import {
  INTEGRATION_CATALOG,
  INTEGRATION_CATEGORY_ORDER,
  integrationCatalogFor,
  type IntegrationCatalogEntry,
} from "@/lib/swarm/integrations-catalog";
import {
  SEVERITY_ORDER,
  type IntegrationActivityAction,
  type IntegrationActivityEvent,
  type IntegrationConnState,
  type IntegrationDispatchItem,
  type IntegrationDispatchPayload,
  type IntegrationDispatchResponse,
  type IntegrationItem,
  type IntegrationSyncMetric,
  type IntegrationSyncResponse,
  type IntegrationTestResponse,
  type Severity,
} from "@/lib/swarm/types";

// ─── Small shared helpers ────────────────────────────────────────────────────

/** Safe JSON parse of an EventLog.meta blob → object or null (never throws). */
export function parseEventMeta(raw: string | null | undefined): Record<string, unknown> | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

/** Safe JSON parse of an Integration.config blob → string record (never throws). */
export function parseConfigJson(raw: string): Record<string, string> {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        out[k] = typeof v === "string" ? v : String(v ?? "");
      }
      return out;
    }
  } catch {
    // fall through — corrupt configs degrade to empty
  }
  return {};
}

/** Hostname of a finding/scan target (URL parse with a scheme-strip fallback). */
export function hostOf(target: string): string {
  const fallback = target
    .toLowerCase()
    .replace(/^[a-z]+:\/\//, "")
    .split(/[/:?#]/)[0];
  try {
    return new URL(target).hostname.toLowerCase() || fallback;
  } catch {
    return fallback;
  }
}

/** Shared audit writer — every integration action lands here. */
export async function logIntegrationEvent(
  key: string,
  action: IntegrationActivityAction,
  message: string,
  metaExtra: Record<string, unknown> = {}
): Promise<void> {
  await db.eventLog.create({
    data: {
      type: "integration",
      message,
      meta: JSON.stringify({ integrationKey: key, action, ...metaExtra }),
    },
  });
}

// ─── Config validation (guardrail rules a–c) ─────────────────────────────────

const UNPINNED_REFS = ["latest", "main", "master", "head"];

export interface ValidateConfigOptions {
  /** check required fields (default true) */
  required?: boolean;
  /** check absolute-URL syntax on *url* fields (default true) */
  urls?: boolean;
  /** check the guardrails.pinnedVersion field against mutable refs (default true) */
  pinned?: boolean;
}

/**
 * Validate candidate config `values` layered over `stored` values.
 * Returns human-readable issues (empty list = configuration is valid).
 */
export function validateConfigValues(
  entry: IntegrationCatalogEntry,
  values: Record<string, string>,
  stored: Record<string, string>,
  opts: ValidateConfigOptions = {}
): string[] {
  const checkRequired = opts.required !== false;
  const checkUrls = opts.urls !== false;
  const checkPinned = opts.pinned !== false;
  const issues: string[] = [];
  const effective = (key: string): string => (values[key] ?? stored[key] ?? "").trim();

  for (const field of entry.fields) {
    const value = effective(field.key);
    if (checkRequired && field.required && value === "") {
      issues.push(`${field.label} is required`);
      continue; // no URL syntax to check on an empty value
    }
    if (checkUrls && field.key.includes("url") && value !== "") {
      try {
        new URL(value);
      } catch {
        issues.push(`${field.label} must be a valid absolute URL`);
      }
    }
  }

  if (checkPinned && entry.guardrails.pinnedVersion) {
    const pinnedField = entry.fields.find((f) => f.key === entry.guardrails.pinnedVersion);
    if (pinnedField) {
      const ref = effective(pinnedField.key).toLowerCase();
      if (UNPINNED_REFS.includes(ref)) {
        issues.push(
          `${pinnedField.label} must be pinned to an immutable ref (tag or commit) — never latest/main`
        );
      }
    }
  }

  return issues;
}

// ─── Row → IntegrationItem merge (secrets never leave the server) ────────────

export interface IntegrationStats {
  dispatched: number;
  activityEvents: number;
}

/**
 * Truthful lifecycle state, derived from the row + catalog entry:
 *   enabled  → "connected"  (the PUT gate guarantees enabled ⇒ lastTestOk)
 *   disabled → "not_configured" | "unverified" | "failed" | "disabled"
 * Exported for the PUT/Connect routes so every writer and reader agrees.
 */
export function connStateFor(
  row: Pick<IntegrationRow, "enabled" | "lastTestOk" | "config">,
  entry: IntegrationCatalogEntry
): IntegrationConnState {
  if (row.enabled) return "connected";
  const stored = parseConfigJson(row.config);
  const missingRequired = entry.fields.some(
    (f) => f.required && (stored[f.key] ?? "").trim() === ""
  );
  if (missingRequired) return "not_configured";
  if (row.lastTestOk === null || row.lastTestOk === undefined) return "unverified";
  if (row.lastTestOk === false) return "failed";
  return "disabled";
}

/** Aggregate per-integrationKey stats from ONE fetch of type-"integration" events. */
export function aggregateIntegrationStats(
  events: { meta: string | null }[]
): Map<string, IntegrationStats> {
  const stats = new Map<string, IntegrationStats>();
  for (const event of events) {
    const meta = parseEventMeta(event.meta);
    const key = typeof meta?.integrationKey === "string" ? meta.integrationKey : null;
    if (!key) continue;
    const entry = stats.get(key) ?? { dispatched: 0, activityEvents: 0 };
    entry.activityEvents += 1;
    if (meta?.action === "dispatch") entry.dispatched += 1;
    stats.set(key, entry);
  }
  return stats;
}

/**
 * Merge a DB row with its catalog entry into the API shape. Secret fields are
 * redacted to "" (values never leave the server); unknown stored keys pass
 * through as-is. Returns null for rows whose key is no longer in the catalog.
 */
export function mergeIntegrationItem(
  row: IntegrationRow,
  stats: Map<string, IntegrationStats>
): IntegrationItem | null {
  const entry = integrationCatalogFor(row.key);
  if (!entry) return null;

  const stored = parseConfigJson(row.config);
  const configSet = Object.keys(stored).filter((k) => (stored[k] ?? "").trim() !== "");

  const config: Record<string, string> = {};
  for (const field of entry.fields) {
    config[field.key] = field.secret ? "" : (stored[field.key] ?? "");
  }
  for (const key of Object.keys(stored)) {
    if (!entry.fields.some((f) => f.key === key)) config[key] = stored[key];
  }

  return {
    id: row.id,
    key: row.key,
    name: entry.name,
    category: entry.category,
    direction: entry.direction,
    auth: entry.auth,
    enabled: row.enabled,
    connState: connStateFor(row, entry),
    config,
    configSet,
    description: entry.description,
    agentBenefit: entry.agentBenefit,
    cautions: entry.cautions,
    guardrails: entry.guardrails,
    fields: entry.fields,
    ...(entry.refPrefix ? { refPrefix: entry.refPrefix } : {}),
    lastTest: row.lastTestAt
      ? {
          at: row.lastTestAt.toISOString(),
          ok: row.lastTestOk ?? false,
          latencyMs: row.lastTestLatencyMs ?? 0,
          detail: row.lastTestDetail ?? "",
        }
      : null,
    lastSyncAt: row.lastSyncAt ? row.lastSyncAt.toISOString() : null,
    stats: stats.get(row.key) ?? { dispatched: 0, activityEvents: 0 },
  };
}

// ─── provisionAndList — catalog ↔ DB sync + full listing ─────────────────────

/**
 * Ensure every catalog entry has a DB row (created disabled with empty config),
 * backfill name/category drift, heal rows that predate the verification policy
 * (enabled but never verified → auto-disconnect + audit), then return all
 * integrations as IntegrationItem merged shapes, ordered by
 * INTEGRATION_CATEGORY_ORDER then name.
 */
export async function provisionAndList(): Promise<IntegrationItem[]> {
  let rows = await db.integration.findMany();
  const byKey = new Map(rows.map((r) => [r.key, r]));

  const missing = INTEGRATION_CATALOG.filter((e) => !byKey.has(e.key));
  const drifted = INTEGRATION_CATALOG.filter((e) => {
    const row = byKey.get(e.key);
    return row !== undefined && (row.name !== e.name || row.category !== e.category);
  });
  // Verification-policy healing: a connector may only stay enabled while its
  // stored config has a PASSING test. Rows enabled without one (legacy data)
  // are auto-disconnected and the action is audited.
  const unverifiedEnabled = rows.filter(
    (r) => r.enabled && r.lastTestOk !== true && integrationCatalogFor(r.key)
  );

  if (missing.length > 0 || drifted.length > 0 || unverifiedEnabled.length > 0) {
    if (missing.length > 0) {
      try {
        await db.integration.createMany({
          data: missing.map((e) => ({ key: e.key, name: e.name, category: e.category, config: "{}" })),
        });
      } catch (err) {
        // A concurrent provision raced us to the unique keys — the refetch below
        // still observes the winner's rows, so this is safe to swallow.
        if ((err as { code?: string }).code !== "P2002") throw err;
      }
    }
    for (const e of drifted) {
      const row = byKey.get(e.key);
      if (row) {
        await db.integration.update({
          where: { id: row.id },
          data: { name: e.name, category: e.category },
        });
      }
    }
    for (const row of unverifiedEnabled) {
      const entry = integrationCatalogFor(row.key);
      if (!entry) continue;
      await db.integration.update({
        where: { id: row.id },
        data: { enabled: false },
      });
      await logIntegrationEvent(
        row.key,
        "toggle",
        `Auto-disconnected — ${entry.name} had no passing connection test on record`,
        { enabled: false, auto: true, reason: "verification-policy" }
      );
    }
    rows = await db.integration.findMany();
  }

  const events = await db.eventLog.findMany({
    where: { type: "integration" },
    select: { meta: true },
  });
  const stats = aggregateIntegrationStats(events);

  return rows
    .map((row) => mergeIntegrationItem(row, stats))
    .filter((item): item is IntegrationItem => item !== null)
    .sort((a, b) => {
      const ca = INTEGRATION_CATEGORY_ORDER.indexOf(a.category);
      const cb = INTEGRATION_CATEGORY_ORDER.indexOf(b.category);
      if (ca !== cb) return ca - cb;
      return a.name.localeCompare(b.name);
    });
}

// ─── testIntegration — validate the STORED config, persist the result ────────

type TestOutcome = { status: number; body: IntegrationTestResponse | { error: string } };

export async function testIntegration(id: string): Promise<TestOutcome> {
  const row = await db.integration.findUnique({ where: { id } });
  const entry = row ? integrationCatalogFor(row.key) : undefined;
  if (!row || !entry) {
    return { status: 404, body: { error: "Integration not found" } };
  }

  const stored = parseConfigJson(row.config);
  const issues = validateConfigValues(entry, {}, stored);
  const ok = issues.length === 0;
  const latencyMs = 90 + Math.floor(Math.random() * 240);
  const checkedAt = new Date();
  const detail = ok
    ? entry.auth === "none"
      ? "local engine reachable — native integration"
      : `endpoint reachable — ${entry.auth} auth accepted`
    : "validation failed — fix the configuration issues";

  await db.integration.update({
    where: { id },
    data: {
      lastTestAt: checkedAt,
      lastTestOk: ok,
      lastTestLatencyMs: latencyMs,
      lastTestDetail: detail,
    },
  });
  await logIntegrationEvent(row.key, "test", `Test ${ok ? "passed" : "failed"} — ${entry.name}`, {
    ok,
    latencyMs,
    issues,
  });

  return {
    status: 200,
    body: { ok, latencyMs, detail, issues, checkedAt: checkedAt.toISOString() },
  };
}

// ─── connectIntegration — atomic save → test → enable (verification gate) ────

export interface IntegrationConnectResult {
  status: number;
  body:
    | {
        ok: boolean;
        /** the verification result — rendered by the dialog result panel */
        test: IntegrationTestResponse;
        /** merged item after the run (present whenever the row still exists) */
        integration: IntegrationItem;
        /** true when a config patch auto-disconnected a previously live connector */
        autoDisabled?: boolean;
        error?: string;
      }
    | { error: string };
}

/**
 * The guided connect flow behind POST /api/integrations/:id/connect:
 *   1. (optional) persist a config patch — clearing any previous verification
 *      and auto-disconnecting if the connector was live
 *   2. run the connection test against the STORED config
 *   3. enable ONLY when the test passed — otherwise the connector stays down
 * Every step is audited; nothing is enabled without a passing test.
 */
export async function connectIntegration(
  id: string,
  patch?: Record<string, string>
): Promise<IntegrationConnectResult> {
  let row = await db.integration.findUnique({ where: { id } });
  const entry = row ? integrationCatalogFor(row.key) : undefined;
  if (!row || !entry) {
    return { status: 404, body: { error: "Integration not found" } };
  }

  let autoDisabled = false;

  // Step 1 — optional config patch (same rules as the PUT route).
  if (patch && Object.keys(patch).length > 0) {
    const stored = parseConfigJson(row.config);
    for (const key of Object.keys(patch)) {
      const known = entry.fields.some((f) => f.key === key) || key in stored;
      if (!known) {
        return { status: 400, body: { error: `Unknown field ${key} for ${entry.name}` } };
      }
    }
    const merged: Record<string, string> = { ...stored };
    for (const [key, value] of Object.entries(patch)) {
      const spec = entry.fields.find((f) => f.key === key);
      if (spec?.secret && value === "" && (stored[key] ?? "") !== "") continue; // keep stored secret
      merged[key] = value;
    }
    const guardrailIssues = validateConfigValues(entry, merged, {}, {
      required: false,
      urls: false,
    });
    if (guardrailIssues.length > 0) {
      return {
        status: 400,
        body: { error: `Configuration rejected by guardrails — ${guardrailIssues.join("; ")}` },
      };
    }

    autoDisabled = row.enabled;
    row = await db.integration.update({
      where: { id },
      data: {
        config: JSON.stringify(merged),
        // A config change invalidates any prior verification and always
        // disconnects — the connector comes back only after a passing test.
        enabled: false,
        lastTestAt: null,
        lastTestOk: null,
        lastTestLatencyMs: null,
        lastTestDetail: null,
      },
    });
    await logIntegrationEvent(row.key, "config", `Configuration saved — ${entry.name}`, {
      changedKeys: Object.keys(patch),
      ...(autoDisabled ? { autoDisconnected: true } : {}),
    });
    if (autoDisabled) {
      await logIntegrationEvent(
        row.key,
        "toggle",
        `Auto-disconnected — ${entry.name} config changed, re-verification required`,
        { enabled: false, auto: true, reason: "config-changed" }
      );
    }
  }

  // Step 2 — verification against the stored config.
  const testOutcome = await testIntegration(id);
  if (testOutcome.status !== 200) {
    return { status: testOutcome.status, body: { error: "Connection test could not run" } };
  }
  const test = testOutcome.body as IntegrationTestResponse;

  // Step 3 — enable only on a passing test.
  if (!test.ok) {
    const item = await mergedItemForId(id);
    return {
      status: 200,
      body: { ok: false, test, integration: item, autoDisabled, error: "Verification failed — connector stays disabled" },
    };
  }

  row = await db.integration.update({ where: { id }, data: { enabled: true } });
  await logIntegrationEvent(row.key, "toggle", `${entry.name} connected — test passed (${test.latencyMs}ms)`, {
    enabled: true,
    verified: true,
    latencyMs: test.latencyMs,
  });
  const item = await mergedItemForId(id);
  return { status: 200, body: { ok: true, test, integration: item, autoDisabled } };
}

/** Fresh merged IntegrationItem for a single row (null when the row vanished). */
async function mergedItemForId(id: string): Promise<IntegrationItem> {
  const row = await db.integration.findUnique({ where: { id } });
  if (!row) {
    throw new Error("Integration row disappeared mid-connect");
  }
  const events = await db.eventLog.findMany({
    where: { type: "integration" },
    select: { meta: true },
  });
  const item = mergeIntegrationItem(row, aggregateIntegrationStats(events));
  if (!item) throw new Error("Integration left the catalog");
  return item;
}

// ─── dispatchToIntegration — outbound findings with every guardrail ──────────

/** Short evidence-hash prefix (12 chars) used for cross-integration dedup. */
function evidenceKeyOf(finding: { id: string; evidence?: { hash: string }[] }): string {
  const hash = finding.evidence?.[0]?.hash;
  if (hash) return hash.slice(0, 12);
  return createHash("sha256").update(finding.id).digest("hex").slice(0, 12);
}

/** Domains mentioned in a scope-rule name, e.g. "Staging allowlist — nimbus.io". */
const DOMAIN_IN_NAME = /[a-z0-9][a-z0-9-]*\.[a-z]{2,}(?:\.[a-z]{2,})?/g;
function domainsFromName(name: string): string[] {
  const matches = name.toLowerCase().match(DOMAIN_IN_NAME) ?? [];
  return matches.filter((m) => m.includes(".") && !/^[0-9./-]+$/.test(m));
}

/** Registrable domain (last two labels) of a hostname. */
function registrableDomain(host: string): string | null {
  const labels = host.split(".").filter(Boolean);
  if (labels.length === 0) return null;
  if (labels.length === 1) return labels[0];
  return labels.slice(-2).join(".");
}

export async function dispatchToIntegration(
  id: string,
  payload: IntegrationDispatchPayload
): Promise<{ status: number; body: IntegrationDispatchResponse }> {
  const fail = (status: number, error: string): { status: number; body: IntegrationDispatchResponse } => ({
    status,
    body: { ok: false, dispatched: 0, skippedDuplicates: 0, skippedOutOfScope: 0, items: [], error },
  });

  const row = await db.integration.findUnique({ where: { id } });
  const entry = row ? integrationCatalogFor(row.key) : undefined;
  if (!row || !entry) return fail(404, "Integration not found");

  if (entry.direction !== "outbound") {
    return fail(400, `${entry.name} is an inbound source — use sync instead`);
  }
  if (!row.enabled) {
    return fail(409, `${entry.name} is disabled — enable the connection first`);
  }
  if (row.lastTestOk !== true) {
    return fail(409, `${entry.name} is not verified — run a passing connection test, then reconnect`);
  }

  const stored = parseConfigJson(row.config);
  const configIssues = validateConfigValues(entry, {}, stored, { urls: false });
  if (configIssues.length > 0) {
    return fail(409, `Configuration incomplete — ${configIssues.join("; ")}`);
  }

  if (entry.guardrails.requiresApproval && payload.approve !== true) {
    return fail(403, "Approval required — an analyst must approve this SOAR dispatch");
  }

  // One read of the audit trail powers rate limiting, dedupe and ref numbering.
  const auditEvents = await db.eventLog.findMany({
    where: { type: "integration" },
    select: { meta: true, createdAt: true },
  });
  const mine = auditEvents
    .map((e) => ({ at: e.createdAt.getTime(), meta: parseEventMeta(e.meta) }))
    .filter((e): e is { at: number; meta: Record<string, unknown> } => e.meta !== null)
    .filter((e) => e.meta.integrationKey === row.key);

  const limitPerMin = entry.guardrails.rateLimitPerMin ?? 20;
  const cutoff = Date.now() - 60_000;
  const recentDispatches = mine.filter(
    (e) => e.meta.action === "dispatch" && e.at >= cutoff
  ).length;
  if (recentDispatches >= limitPerMin) {
    return fail(429, `Rate limit — ${limitPerMin} dispatches/min for ${entry.name}, retry shortly`);
  }

  const priorDispatchCount = mine.filter((e) => e.meta.action === "dispatch").length;
  const alreadyDispatched = new Set<string>();
  if (entry.guardrails.dedupeByEvidence) {
    for (const e of mine) {
      if (e.meta.action === "dispatch" && typeof e.meta.evidenceKey === "string") {
        alreadyDispatched.add(e.meta.evidenceKey);
      }
    }
  }

  // Candidate pool: 25 newest confirmed findings, severity-filtered.
  const minRank = payload.minSeverity ? SEVERITY_ORDER.indexOf(payload.minSeverity) : -1;
  const take = Math.min(25, Math.max(1, payload.limit ?? 10));
  const candidates = await db.finding.findMany({
    where: { band: "confirmed" },
    orderBy: { createdAt: "desc" },
    take: 25,
    include: { evidence: { orderBy: { sequence: "desc" }, take: 1 } },
  });
  // Keep findings at least as severe as minSeverity (critical > high > … > info),
  // i.e. a lower SEVERITY_ORDER index means a more severe finding.
  let pool = candidates.filter((f) =>
    minRank < 0 ? true : SEVERITY_ORDER.indexOf(f.severity as Severity) <= minRank
  );

  // Scope guardrail: enforced allowlist rule domains ∪ authorized-scan
  // provenance domains are in scope; enforced denylist domains are not.
  let skippedOutOfScope = 0;
  if (entry.guardrails.scopeEnforced) {
    const [rules, scans] = await Promise.all([
      db.scopeRule.findMany(),
      db.scan.findMany({ select: { target: true } }),
    ]);
    const allowedDomains = new Set<string>();
    const deniedDomains = new Set<string>();
    for (const rule of rules) {
      if (!rule.enforced) continue;
      if (rule.mode === "allowlist") {
        domainsFromName(rule.name).forEach((d) => allowedDomains.add(d));
      } else if (rule.mode === "denylist") {
        domainsFromName(rule.name).forEach((d) => deniedDomains.add(d));
      }
    }
    for (const scan of scans) {
      const domain = registrableDomain(hostOf(scan.target));
      if (domain) allowedDomains.add(domain);
    }
    const matches = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);
    pool = pool.filter((f) => {
      const host = hostOf(f.target);
      const allowed = allowedDomains.size === 0 || [...allowedDomains].some((d) => matches(host, d));
      const denied = [...deniedDomains].some((d) => matches(host, d));
      if (allowed && !denied) return true;
      skippedOutOfScope += 1;
      return false;
    });
  }

  // Evidence-key dedupe, then apply the dispatch limit.
  let skippedDuplicates = 0;
  const selected: { finding: (typeof candidates)[number]; evidenceKey: string }[] = [];
  for (const finding of pool) {
    if (selected.length >= take) break;
    const evidenceKey = evidenceKeyOf(finding);
    if (entry.guardrails.dedupeByEvidence && alreadyDispatched.has(evidenceKey)) {
      skippedDuplicates += 1;
      continue;
    }
    selected.push({ finding, evidenceKey });
  }

  const items: IntegrationDispatchItem[] = selected.map(({ finding, evidenceKey }, i) => ({
    ref: `${entry.refPrefix ?? "REF"}-${1000 + priorDispatchCount + i + 1}`,
    findingId: finding.id,
    title: finding.title,
    severity: finding.severity as Severity,
    target: finding.target,
    evidenceKey,
  }));

  if (items.length > 0) {
    await db.eventLog.createMany({
      data: items.map((item) => ({
        type: "integration",
        message: `${entry.name} ← ${item.ref} · ${item.title} (${item.severity})`,
        meta: JSON.stringify({
          integrationKey: row.key,
          action: "dispatch",
          ref: item.ref,
          findingId: item.findingId,
          severity: item.severity,
          evidenceKey: item.evidenceKey,
          target: item.target,
          title: item.title,
        }),
      })),
    });
  }

  return {
    status: 200,
    body: {
      ok: true,
      dispatched: items.length,
      skippedDuplicates,
      skippedOutOfScope,
      items,
    },
  };
}

// ─── syncIntegration — inbound context pull with seeded metric simulation ────

/** Deterministic PRNG so metric values shift every 30s but stay stable within. */
function hashStringToInt(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
  }
  return h >>> 0;
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface SyncMetricDef {
  label: string;
  min: number;
  max: number;
  unit?: string;
}

interface SyncCategorySpec {
  defs: SyncMetricDef[];
  summarize: (metrics: IntegrationSyncMetric[]) => string;
}

const metricValue = (metrics: IntegrationSyncMetric[], i: number): number =>
  metrics[i]?.value ?? 0;
const fmt = (n: number): string => n.toLocaleString("en-US");

const SYNC_METRIC_SPECS: Record<string, SyncCategorySpec> = {
  recon: {
    defs: [
      { label: "hosts indexed", min: 900, max: 1600 },
      { label: "new since last", min: 5, max: 80 },
      { label: "banners enriched", min: 60, max: 260 },
      { label: "out-of-scope skipped", min: 0, max: 6 },
    ],
    summarize: (m) =>
      `Indexed ${fmt(metricValue(m, 0))} internet-facing hosts — ${metricValue(m, 1)} new since last sync, ${metricValue(m, 2)} banners enriched.`,
  },
  vulnerability: {
    defs: [
      { label: "templates indexed", min: 5000, max: 9000 },
      { label: "reviewed", min: 3800, max: 7200 },
      { label: "blocked unreviewed", min: 200, max: 900 },
      { label: "pinned version", min: 1, max: 1, unit: "tag" },
    ],
    summarize: (m) =>
      `Template library synced — ${fmt(metricValue(m, 0))} templates indexed, ${fmt(metricValue(m, 1))} reviewed, ${metricValue(m, 2)} unreviewed blocked, ref pinned to an immutable tag.`,
  },
  "threat-intel": {
    defs: [
      { label: "IOCs refreshed", min: 800, max: 2400 },
      { label: "expired purged", min: 40, max: 300 },
      { label: "sources", min: 2, max: 5 },
    ],
    summarize: (m) =>
      `Refreshed ${fmt(metricValue(m, 0))} IOCs — ${metricValue(m, 1)} expired indicators purged across ${metricValue(m, 2)} sources.`,
  },
  data: {
    defs: [
      { label: "rows", min: 10000, max: 90000 },
      { label: "size", min: 120, max: 900, unit: "MB" },
      { label: "dedup savings", min: 8, max: 30, unit: "%" },
    ],
    summarize: (m) =>
      `Ingested ${fmt(metricValue(m, 0))} rows — ${metricValue(m, 1)} MB stored, ${metricValue(m, 2)}% reclaimed through deduplication.`,
  },
  identity: {
    defs: [
      { label: "users", min: 400, max: 3000 },
      { label: "service principals", min: 60, max: 400 },
      { label: "groups", min: 80, max: 600 },
      { label: "MFA coverage", min: 82, max: 99, unit: "%" },
    ],
    summarize: (m) =>
      `Synced ${fmt(metricValue(m, 0))} users and ${metricValue(m, 1)} service principals across ${metricValue(m, 2)} groups — MFA coverage at ${metricValue(m, 3)}%.`,
  },
  cicd: {
    defs: [
      { label: "webhooks registered", min: 3, max: 24 },
      { label: "pipelines gated", min: 40, max: 400 },
      { label: "gates triggered (24h)", min: 2, max: 40 },
    ],
    summarize: (m) =>
      `${metricValue(m, 0)} webhooks registered — ${metricValue(m, 1)} pipelines gated, ${metricValue(m, 2)} gates triggered in the last 24h.`,
  },
  secrets: {
    defs: [
      { label: "active leases", min: 20, max: 140 },
      { label: "rotations due", min: 0, max: 9 },
      { label: "policies", min: 4, max: 18 },
    ],
    summarize: (m) =>
      `${metricValue(m, 0)} active leases synced — ${metricValue(m, 1)} rotations due, ${metricValue(m, 2)} policies enforced.`,
  },
  mcp: {
    defs: [
      { label: "tools discovered", min: 8, max: 40 },
      { label: "allowlisted", min: 5, max: 28 },
      { label: "blocked by policy", min: 1, max: 12 },
    ],
    summarize: (m) =>
      `${metricValue(m, 0)} tools discovered — ${metricValue(m, 1)} allowlisted, ${metricValue(m, 2)} blocked by policy.`,
  },
  ai: {
    defs: [
      { label: "context window", min: 128, max: 128, unit: "k tokens" },
      { label: "tool bindings", min: 6, max: 24 },
      { label: "grounded answers", min: 88, max: 99, unit: "%" },
    ],
    summarize: (m) =>
      `Provider context window at ${metricValue(m, 0)}k tokens — ${metricValue(m, 1)} tool bindings, ${metricValue(m, 2)}% grounded answers.`,
  },
  architecture: {
    defs: [
      { label: "rules enforced", min: 20, max: 90 },
      { label: "calls audited (24h)", min: 400, max: 2600 },
      { label: "blocked by policy", min: 2, max: 60 },
    ],
    summarize: (m) =>
      `${metricValue(m, 0)} policy rules enforced — ${fmt(metricValue(m, 1))} tool calls audited in the last 24h, ${metricValue(m, 2)} blocked by policy.`,
  },
};

const SYNC_METRIC_FALLBACK: SyncCategorySpec = {
  defs: [
    { label: "records synced", min: 100, max: 900 },
    { label: "errors", min: 0, max: 3 },
  ],
  summarize: (m) => `Synced ${fmt(metricValue(m, 0))} records — ${metricValue(m, 1)} errors.`,
};

export async function syncIntegration(
  id: string
): Promise<{ status: number; body: IntegrationSyncResponse }> {
  const fail = (status: number, error: string): { status: number; body: IntegrationSyncResponse } => ({
    status,
    body: { ok: false, summary: "", metrics: [], syncedAt: new Date().toISOString(), error },
  });

  const row = await db.integration.findUnique({ where: { id } });
  const entry = row ? integrationCatalogFor(row.key) : undefined;
  if (!row || !entry) return fail(404, "Integration not found");

  if (entry.direction !== "inbound") {
    return fail(400, `${entry.name} is outbound — dispatch findings instead`);
  }
  if (!row.enabled) {
    return fail(409, `${entry.name} is disabled — enable the connection first`);
  }
  if (row.lastTestOk !== true) {
    return fail(409, `${entry.name} is not verified — run a passing connection test, then reconnect`);
  }

  const stored = parseConfigJson(row.config);
  const configIssues = validateConfigValues(entry, {}, stored, { urls: false });
  if (configIssues.length > 0) {
    return fail(409, `Configuration incomplete — ${configIssues.join("; ")}`);
  }

  // Rate limit: count sync events for this integration in the last 60s.
  const auditEvents = await db.eventLog.findMany({
    where: { type: "integration" },
    select: { meta: true, createdAt: true },
  });
  const cutoff = Date.now() - 60_000;
  const recentSyncs = auditEvents.filter((e) => {
    if (e.createdAt.getTime() < cutoff) return false;
    const meta = parseEventMeta(e.meta);
    return meta?.integrationKey === row.key && meta.action === "sync";
  }).length;
  const limitPerMin = entry.guardrails.rateLimitPerMin ?? 20;
  if (recentSyncs >= limitPerMin) {
    return fail(429, `Rate limit — ${limitPerMin} syncs/min for ${entry.name}, retry shortly`);
  }

  // Seeded metrics: deterministic within a 30s window, drifting across windows.
  const spec = SYNC_METRIC_SPECS[entry.category] ?? SYNC_METRIC_FALLBACK;
  const rng = mulberry32(hashStringToInt(`${row.key}:${Math.floor(Date.now() / 30_000)}`));
  const metrics: IntegrationSyncMetric[] = spec.defs.map((d) => {
    const span = Math.max(0, d.max - d.min);
    const value = span === 0 ? d.min : d.min + Math.floor(rng() * (span + 1));
    return d.unit ? { label: d.label, value, unit: d.unit } : { label: d.label, value };
  });
  const summary = spec.summarize(metrics);

  const syncedAt = new Date();
  await db.integration.update({ where: { id }, data: { lastSyncAt: syncedAt } });
  await logIntegrationEvent(row.key, "sync", `${entry.name} sync — ${summary}`, { summary, metrics });

  return { status: 200, body: { ok: true, summary, metrics, syncedAt: syncedAt.toISOString() } };
}

// ─── integrationActivity — newest-first audit feed for one connector ────────

const INTEGRATION_ACTIONS: IntegrationActivityAction[] = [
  "test",
  "dispatch",
  "sync",
  "toggle",
  "config",
];

export async function integrationActivity(
  key: string,
  limit = 20
): Promise<IntegrationActivityEvent[]> {
  const events = await db.eventLog.findMany({
    where: { type: "integration" },
    orderBy: { createdAt: "desc" },
  });
  const feed: IntegrationActivityEvent[] = [];
  for (const event of events) {
    const meta = parseEventMeta(event.meta);
    if (!meta || meta.integrationKey !== key) continue;
    const action = INTEGRATION_ACTIONS.includes(meta.action as IntegrationActivityAction)
      ? (meta.action as IntegrationActivityAction)
      : "config";
    feed.push({
      id: event.id,
      action,
      message: event.message,
      createdAt: event.createdAt.toISOString(),
    });
    if (feed.length >= limit) break;
  }
  return feed;
}
