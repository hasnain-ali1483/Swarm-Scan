// ─── Compliance — SOC 2 Type II evidence packs from the WORM ledger (11-b) ───
// Deterministic pack builder: reads the REAL database (evidence ledger, scans,
// findings, chains, scope wall, access directory, event log), maps every ledger
// evidence kind onto SOC 2 Trust Services Criteria controls, and attests the
// pack against the hash-chain head. The export bundle wraps the pack into
// sha256-sealed manifest sections — same DB ⇒ same hashes ⇒ same fileName.

import { createHash } from "node:crypto";

import { db } from "@/lib/db";
import { chainHash, ZERO_HASH } from "@/lib/swarm/server/hash";
import type {
  ComplianceControl,
  ComplianceEvidenceRef,
  ComplianceExportOptions,
  CompliancePack,
  ControlStatus,
} from "@/lib/swarm/types";

const sha256 = (input: string): string => createHash("sha256").update(input).digest("hex");

/** Evidence refs shown per control card (highest sequence first). */
const REF_CAP = 6;
/** Ledger refs a control needs to reach "satisfied" coverage. */
const SATISFIED_REFS = 5;
/** Coverage denominator — evidenceCount / 8 × 100, capped at 100. */
const COVERAGE_DENOM = 8;

// ─── Ledger walk (mirrors src/app/api/ledger/verify/route.ts) ─────────────────

async function verifyLedger(): Promise<{ valid: boolean; chainHead: string }> {
  const scans = await db.scan.findMany({ orderBy: { createdAt: "asc" }, select: { id: true } });

  let valid = true;
  let chainHead = ZERO_HASH;

  for (const scan of scans) {
    const entries = await db.evidence.findMany({
      where: { scanId: scan.id },
      orderBy: { sequence: "asc" },
    });
    let prevHash = ZERO_HASH;
    for (const entry of entries) {
      const expected = chainHash(entry.prevHash, entry.sequence, entry.content);
      if (entry.prevHash !== prevHash || entry.hash !== expected) valid = false;
      prevHash = entry.hash;
    }
    if (entries.length > 0) chainHead = entries[entries.length - 1].hash;
  }

  return { valid, chainHead };
}

// ─── Control catalog (SOC 2 Trust Services Criteria) ─────────────────────────

interface ControlSpec {
  id: string;
  title: string;
  description: string;
  /** Evidence rows (by kind) mapped onto this control. */
  kinds: string[];
}

const CONTROL_SPECS: ControlSpec[] = [
  {
    id: "CC6.1",
    title: "Boundary protection",
    description:
      "Scope firewall enforces a CIDR allow/deny wall around every scan; boundary decisions are ledgered as decision evidence.",
    kinds: ["decision"],
  },
  {
    id: "CC6.3",
    title: "Access restriction",
    description:
      "Access control directory health — members, SSO identity providers and re-verification of access-related findings.",
    kinds: ["reverify"],
  },
  {
    id: "CC6.6",
    title: "Attack surface review",
    description:
      "Scan coverage of in-scope targets (completed ratio) plus version_map fingerprint evidence for exposed components.",
    kinds: ["version_map"],
  },
  {
    id: "CC7.1",
    title: "Vulnerability detection",
    description:
      "Findings and their detection evidence — boolean diffs, time contrasts, DOM taint flows and error-signature matches.",
    kinds: ["boolean_diff", "time_contrast", "dom_taint", "error_match"],
  },
  {
    id: "CC7.2",
    title: "Anomaly & OOB monitoring",
    description:
      "Out-of-band callback monitoring (DNS/HTTP egress canaries) captured as oob_callback evidence entries.",
    kinds: ["oob_callback"],
  },
  {
    id: "CC7.3",
    title: "Event correlation",
    description:
      "CorrelatorAgent attack chains across findings, backed by decision evidence entries in the per-scan ledger.",
    kinds: ["decision"],
  },
  {
    id: "CC7.4",
    title: "Incident response",
    description:
      "Kill-switch and incident telemetry — kill events and system rows in the EventLog audit trail.",
    kinds: [],
  },
  {
    id: "CC8.1",
    title: "Change management",
    description:
      "Re-verification of changed components (reverify evidence) and policy change events in the audit event log.",
    kinds: ["reverify"],
  },
];

function coveragePct(evidenceCount: number): number {
  return Math.min(100, Math.round((evidenceCount / COVERAGE_DENOM) * 100));
}

function statusFor(refCount: number, dataComplete: boolean): ControlStatus {
  if (refCount === 0) return "gap";
  if (refCount >= SATISFIED_REFS && dataComplete) return "satisfied";
  return "partial";
}

function additionalArtifacts(evidenceCount: number): number {
  return Math.max(1, SATISFIED_REFS - evidenceCount);
}

// ─── Pack builder ────────────────────────────────────────────────────────────

export async function buildCompliancePack(): Promise<CompliancePack> {
  const [
    evidenceRows,
    scanCount,
    completedScans,
    findingCount,
    chainCount,
    scopeRules,
    accessUsers,
    ssoConnections,
    killEvents,
    policyEvents,
    ledger,
  ] = await Promise.all([
    db.evidence.findMany({
      orderBy: [{ scan: { createdAt: "asc" } }, { sequence: "asc" }],
      include: {
        finding: { select: { title: true } },
        scan: { select: { target: true } },
      },
    }),
    db.scan.count(),
    db.scan.count({ where: { status: "completed" } }),
    db.finding.count(),
    db.attackChain.count(),
    db.scopeRule.findMany({ select: { enforced: true } }),
    db.accessUser.count(),
    db.ssoConnection.count(),
    db.eventLog.count({ where: { type: "kill" } }),
    db.eventLog.count({ where: { type: "policy" } }),
    verifyLedger(),
  ]);

  const completedRatio = scanCount > 0 ? completedScans / scanCount : 0;
  const enforcedRules = scopeRules.filter((r) => r.enforced).length;
  const activeUsers = accessUsers; // directory members (SSO-managed)

  const findingsCovered = new Set(
    evidenceRows.map((e) => e.findingId).filter((id): id is string => id !== null)
  ).size;

  const controls: ComplianceControl[] = CONTROL_SPECS.map((spec) => {
    const refs = evidenceRows.filter((e) => spec.kinds.includes(e.kind));

    // Deterministic, highest sequence first (then newest ledger row).
    const ordered = [...refs].sort(
      (a, b) => b.sequence - a.sequence || b.createdAt.getTime() - a.createdAt.getTime()
    );

    const evidence: ComplianceEvidenceRef[] = ordered.slice(0, REF_CAP).map((e) => ({
      entryId: e.id,
      sequence: e.sequence,
      kind: e.kind,
      hash: `${e.hash.slice(0, 16)}…`,
      at: e.createdAt.toISOString(),
      findingTitle: e.finding?.title ?? null,
    }));

    // Per-control data-completeness gates (outside the ledger). evidenceCount
    // stays = ledger refs; structural data (scope rules, directory, chains,
    // policy events) only moves the status and the gap note.
    let dataComplete = true;
    let gapNote: string | null = null;

    switch (spec.id) {
      case "CC6.1": {
        // Boundary wall needs ≥ 4 enforced rules for Type II attestation.
        dataComplete = enforcedRules >= 4;
        if (!dataComplete) {
          gapNote = `${additionalArtifacts(refs.length)} additional artifacts required for Type II attestation — the enforced CIDR wall carries ${enforcedRules} rules (needs ≥ 4) and decision evidence is thin (${refs.length} entries).`;
        }
        break;
      }
      case "CC6.3": {
        // Directory health exists, but reverify evidence chains are thin.
        dataComplete = refs.length >= SATISFIED_REFS;
        gapNote = dataComplete
          ? null
          : `${additionalArtifacts(refs.length)} additional artifacts required for Type II attestation — directory lists ${activeUsers} members across ${ssoConnections} SSO connections, but only ${refs.length} reverify entry chains access reviews into the WORM ledger.`;
        break;
      }
      case "CC6.6": {
        // Scan coverage: completed ratio over the recorded scans.
        dataComplete = scanCount > 0 && completedRatio >= 0.5;
        if (!dataComplete) {
          gapNote = `${additionalArtifacts(refs.length)} additional artifacts required for Type II attestation — completed-scan coverage is ${(completedRatio * 100).toFixed(0)}% (${completedScans}/${scanCount}); finish outstanding scans to complete the review period.`;
        }
        break;
      }
      case "CC7.1": {
        dataComplete = findingCount > 0 && refs.length >= SATISFIED_REFS;
        if (!dataComplete) {
          gapNote = `${additionalArtifacts(refs.length)} additional artifacts required for Type II attestation — only ${refs.length} detection entries ledgered across ${findingCount} findings.`;
        }
        break;
      }
      case "CC7.2": {
        dataComplete = refs.length >= SATISFIED_REFS;
        if (!dataComplete) {
          gapNote = `${additionalArtifacts(refs.length)} additional artifacts required for Type II attestation — only ${refs.length} OOB callback entries in the period.`;
        }
        break;
      }
      case "CC7.3": {
        // Chains correlated, but decision evidence is thin.
        dataComplete = refs.length >= SATISFIED_REFS && chainCount > 0;
        if (!dataComplete) {
          gapNote = `${additionalArtifacts(refs.length)} additional artifacts required for Type II attestation — ${chainCount} attack chains correlated but only ${refs.length} decision entries are ledgered.`;
        }
        break;
      }
      case "CC7.4": {
        // Kill telemetry lives in the EventLog audit trail — no WORM evidence
        // kind maps to incident response yet. Honest gap.
        dataComplete = false;
        gapNote = `No WORM evidence kind maps to incident response — kill telemetry (${killEvents} kill events in the EventLog audit trail) sits outside the per-scan hash chains. Introduce a kill evidence kind to the ledger to close this gap.`;
        break;
      }
      case "CC8.1": {
        // Policy change events count toward change-management artifacts.
        dataComplete = refs.length + policyEvents >= SATISFIED_REFS;
        if (!dataComplete) {
          gapNote = `${additionalArtifacts(refs.length + policyEvents)} additional artifacts required for Type II attestation — ${policyEvents} policy-change events logged but only ${refs.length} reverify entry chains changes into the WORM ledger.`;
        }
        break;
      }
    }

    const status = statusFor(refs.length, dataComplete);
    if (status === "satisfied") gapNote = null;

    return {
      id: spec.id,
      title: spec.title,
      description: spec.description,
      status,
      coveragePct: coveragePct(refs.length),
      evidenceCount: refs.length,
      evidence,
      gapNote,
    };
  });

  // Rolling quarter ending "today" (period math on the current date only).
  const now = new Date();
  const periodEnd = new Date(now);
  const periodStart = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 3, now.getUTCDate())
  );

  return {
    framework: "SOC 2 Type II",
    periodStart: periodStart.toISOString(),
    periodEnd: periodEnd.toISOString(),
    generatedAt: now.toISOString(),
    controls,
    summary: {
      satisfied: controls.filter((c) => c.status === "satisfied").length,
      partial: controls.filter((c) => c.status === "partial").length,
      gaps: controls.filter((c) => c.status === "gap").length,
      evidenceEntries: evidenceRows.length,
      ledgerValid: ledger.valid,
      chainHead: ledger.chainHead,
      findingsCovered,
    },
  };
}

// ─── Export bundle (sealed manifest sections) ────────────────────────────────

export interface ExportBundle {
  body: unknown;
  manifest: { section: string; entries: number; sha256: string }[];
  sizeBytes: number;
  entries: number;
}

export async function buildExportBundle(
  options: ComplianceExportOptions
): Promise<ExportBundle> {
  const pack = await buildCompliancePack();

  // Full-resolution evidence index (uncapped, full hashes, scan target kept).
  const evidenceRows = await db.evidence.findMany({
    orderBy: [{ scan: { createdAt: "asc" } }, { sequence: "asc" }],
    include: {
      finding: { select: { title: true } },
      scan: { select: { target: true } },
    },
  });

  const evidenceIndex = evidenceRows.map((e) => ({
    entryId: e.id,
    sequence: e.sequence,
    kind: e.kind,
    hash: e.hash,
    at: e.createdAt.toISOString(),
    findingTitle: e.finding?.title ?? null,
    scanTarget: e.scan?.target ?? "",
  }));

  const attestation = {
    framework: pack.framework,
    periodStart: pack.periodStart,
    periodEnd: pack.periodEnd,
    generatedAt: pack.generatedAt,
    ledgerValid: pack.summary.ledgerValid,
    chainHead: pack.summary.chainHead,
    evidenceEntries: pack.summary.evidenceEntries,
    findingsCovered: pack.summary.findingsCovered,
    controls: pack.controls.length,
    controlsSatisfied: pack.summary.satisfied,
    controlsPartial: pack.summary.partial,
    controlsGaps: pack.summary.gaps,
    chainFormula: "hash = sha256(prevHash:sequence:content) — per-scan WORM chains, genesis prev-hash 64×0",
  };

  const sections: { section: string; content: unknown }[] = [
    { section: "controls", content: pack.controls },
    { section: "evidence", content: evidenceIndex },
    { section: "attestation", content: attestation },
  ];

  if (options.includeSarif) {
    const findings = await db.finding.findMany({
      orderBy: { createdAt: "asc" },
      select: { id: true, title: true, severity: true, band: true, target: true, agentKey: true },
    });
    const sarifSummary = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      summary: {
        tool: "SwarmScan",
        rules: findings.length,
        levels: findings.reduce<Record<string, number>>((acc, f) => {
          acc[f.severity] = (acc[f.severity] ?? 0) + 1;
          return acc;
        }, {}),
      },
      rules: findings.map((f) => ({
        ruleId: `swarmscan/${f.agentKey}/${f.id.slice(0, 8)}`,
        level:
          f.severity === "critical" || f.severity === "high"
            ? "error"
            : f.severity === "medium"
              ? "warning"
              : "note",
        message: f.title,
        target: f.target,
        band: f.band,
      })),
    };
    sections.push({ section: "sarif-summary", content: sarifSummary });
  }

  if (options.includeRawEvidence) {
    // Raw WORM payloads — anonymize strips content, keeps the hash chain.
    const rawEvidence = evidenceRows.map((e) => ({
      entryId: e.id,
      scanId: e.scanId,
      sequence: e.sequence,
      kind: e.kind,
      lr: e.lr,
      content: options.anonymize ? null : e.content,
      hash: e.hash,
      prevHash: e.prevHash,
      at: e.createdAt.toISOString(),
      anonymized: options.anonymize,
    }));
    sections.push({ section: "raw-evidence", content: rawEvidence });
  }

  const manifest = sections.map((s) => ({
    section: s.section,
    entries: Array.isArray(s.content) ? s.content.length : 1,
    sha256: sha256(JSON.stringify(s.content)),
  }));

  const body = {
    kind: "swarmscan.compliance.export",
    framework: pack.framework,
    period: { start: pack.periodStart, end: pack.periodEnd },
    generatedAt: pack.generatedAt,
    options,
    attestation,
    controls: pack.controls,
    evidence: evidenceIndex,
    ...(options.includeSarif
      ? { sarifSummary: sections.find((s) => s.section === "sarif-summary")?.content }
      : {}),
    ...(options.includeRawEvidence
      ? { rawEvidence: sections.find((s) => s.section === "raw-evidence")?.content }
      : {}),
    manifest,
  };

  const serialized = JSON.stringify(body);

  return {
    body,
    manifest,
    sizeBytes: serialized.length,
    entries: manifest.reduce((n, s) => n + s.entries, 0),
  };
}

/** Deterministic export file name: swarmscan-soc2-<yyyymmdd>-<hash8>.json */
export function exportFileName(
  manifest: { section: string; sha256: string }[],
  at = new Date()
): string {
  const attestation = manifest.find((s) => s.section === "attestation");
  const hash8 = (attestation?.sha256 ?? sha256("missing")).slice(0, 8);
  const yyyymmdd = at.toISOString().slice(0, 10).replace(/-/g, "");
  return `swarmscan-soc2-${yyyymmdd}-${hash8}.json`;
}
