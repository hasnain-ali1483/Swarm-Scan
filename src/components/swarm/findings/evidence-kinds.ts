// ─── Evidence kind presentation metadata (shared: findings + ledger) ─────────
// Maps EvidenceKind → label + hint colors. Lives next to the findings view but
// imported by the ledger view as well (both render evidence records).

import type { EvidenceKind } from "@/lib/swarm/types";

export interface EvidenceKindMeta {
  label: string;
  badge: string;
  dot: string;
}

export const EVIDENCE_KINDS: Record<EvidenceKind, EvidenceKindMeta> = {
  oob_callback: {
    label: "OOB Callback",
    badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
    dot: "bg-emerald-500",
  },
  dom_taint: {
    label: "DOM Taint",
    badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
    dot: "bg-emerald-500",
  },
  boolean_diff: {
    label: "Boolean Diff",
    badge: "border-amber-500/40 bg-amber-500/10 text-amber-400",
    dot: "bg-amber-500",
  },
  error_match: {
    label: "Error Match",
    badge: "border-amber-500/40 bg-amber-500/10 text-amber-400",
    dot: "bg-amber-500",
  },
  time_contrast: {
    label: "Time Contrast",
    badge: "border-zinc-500/40 bg-zinc-500/10 text-zinc-300",
    dot: "bg-zinc-400",
  },
  version_map: {
    label: "Version Map",
    badge: "border-zinc-500/40 bg-zinc-500/10 text-zinc-300",
    dot: "bg-zinc-400",
  },
  reverify: {
    label: "Re-verify",
    badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
    dot: "bg-emerald-500",
  },
  decision: {
    label: "Decision",
    badge: "border-zinc-500/40 bg-zinc-500/10 text-zinc-300",
    dot: "bg-zinc-400",
  },
};

const FALLBACK: EvidenceKindMeta = {
  label: "Evidence",
  badge: "border-zinc-500/40 bg-zinc-500/10 text-zinc-300",
  dot: "bg-zinc-400",
};

/** Safe lookup — unknown kinds (future engine versions) fall back to zinc. */
export function evidenceKindMeta(kind: string): EvidenceKindMeta {
  return (EVIDENCE_KINDS as Record<string, EvidenceKindMeta | undefined>)[kind] ?? FALLBACK;
}
