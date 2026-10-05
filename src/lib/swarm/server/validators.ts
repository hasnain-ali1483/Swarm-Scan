// ─── Shared zod schemas for control-plane API routes ─────────────────────────

import { z } from "zod";
import { AGENTS_CATALOG } from "@/lib/swarm/agents-catalog";

export const AGENT_KEYS = AGENTS_CATALOG.map((a) => a.key) as [string, ...string[]];

export const SEVERITY_ENUM = ["critical", "high", "medium", "low", "info"] as const;
export const BAND_ENUM = ["suspected", "likely", "confirmed"] as const;
export const EVIDENCE_KIND_ENUM = [
  "oob_callback",
  "boolean_diff",
  "time_contrast",
  "error_match",
  "dom_taint",
  "version_map",
  "reverify",
  "decision",
] as const;
export const AGENT_RUN_STATUS_ENUM = [
  "dormant",
  "pending",
  "running",
  "done",
  "blocked",
  "skipped",
  "killed",
] as const;

export const scopeRuleSchema = z.object({
  name: z.string().trim().min(1).max(120),
  cidrs: z
    .array(
      z
        .string()
        .trim()
        .min(1)
        .refine((c) => c.includes("/"), "each cidr must look like a CIDR (e.g. 203.0.113.0/24)")
    )
    .min(1),
  mode: z.enum(["allowlist", "denylist"]),
  enforced: z.boolean(),
});
