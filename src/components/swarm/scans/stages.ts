// ─── DAG stage helpers shared by the scan wizard and pipeline ────────────────
// No "use client" needed — pure constants/functions used from client components.

import { AGENTS_CATALOG, AGENT_BY_KEY, STATIC_AGENT_KEYS } from "@/lib/swarm/agents-catalog";
import type { ScanProfile } from "@/lib/swarm/types";

export const STAGE_LABELS: Record<number, string> = {
  0: "Recon & OSINT",
  1: "Fingerprint & Perimeter",
  2: "Surface Discovery & Routing",
  3: "Exploitation & Poisoning",
  4: "Depth, Authz & Identity",
  5: "Correlation, Fusion & Post",
};

export const STAGES: number[] = Array.from(
  new Set(AGENTS_CATALOG.map((a) => a.stage))
).sort((a, b) => a - b);

/** Selectable agents (dynamic agents spawn at runtime — never in the plan). */
export const ALL_AGENT_KEYS: string[] = STATIC_AGENT_KEYS;

/** Quick profile: 6 agents, fast triage (stages 0–3). */
export const QUICK_AGENT_KEYS: string[] = [
  "recon",
  "fingerprint",
  "crawler",
  "ssrf",
  "injection",
  "xss",
];

export function defaultAgentsFor(profile: ScanProfile): string[] {
  return profile === "quick" ? QUICK_AGENT_KEYS : ALL_AGENT_KEYS;
}

export function agentsInStage(stage: number) {
  return AGENTS_CATALOG.filter((a) => a.stage === stage);
}

export function isDataTouching(key: string): boolean {
  return AGENT_BY_KEY[key]?.safetyClass === "data-touching";
}
