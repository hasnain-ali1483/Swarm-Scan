// ─── Policy kind metadata: badges, labels, default Rego templates ─────────────

export const POLICY_KINDS = [
  "rate_limit",
  "payload_class",
  "time_window",
  "target_deny",
  "data_touching",
] as const;

export type PolicyKind = (typeof POLICY_KINDS)[number];

export const KIND_BADGE: Record<string, string> = {
  rate_limit: "bg-zinc-500/15 text-zinc-300 border-zinc-500/40",
  payload_class: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  time_window: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
  target_deny: "bg-red-500/15 text-red-400 border-red-500/40",
  data_touching: "bg-amber-500/15 text-amber-400 border-amber-500/40",
};

export const KIND_LABEL: Record<string, string> = {
  rate_limit: "rate limit",
  payload_class: "payload class",
  time_window: "time window",
  target_deny: "target deny",
  data_touching: "data-touching",
};

export function kindBadgeClass(kind: string): string {
  return KIND_BADGE[kind] ?? "bg-zinc-500/15 text-zinc-300 border-zinc-500/40";
}

export function kindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind.replace(/_/g, " ");
}

export function kindChipTitle(kind: string): string {
  switch (kind) {
    case "rate_limit":
      return "Caps request rate per agent/target";
    case "payload_class":
      return "Gates payload classes (destructive semantics denied by default)";
    case "time_window":
      return "Restricts aggressive scanning to approved windows";
    case "target_deny":
      return "Hard blocklist — deny-listed hosts never receive probes";
    case "data_touching":
      return "Guards data-touching agent states with approval gates";
    default:
      return kind;
  }
}

export function defaultRegoForKind(kind: string): string {
  switch (kind) {
    case "rate_limit":
      return `package swarmscan.policy

# Rate limit — evaluated per request by the control plane
default allow = true

max_requests_per_minute := 240

violate[msg] {
  input.agent.requests_last_minute > max_requests_per_minute
  msg := sprintf(
    "rate limit exceeded for %s: %d > %d/min",
    [input.agent.key, input.agent.requests_last_minute, max_requests_per_minute],
  )
}`;
    case "payload_class":
      return `package swarmscan.policy

# Payload class gate — destructive semantics denied by default
default allow = true

denied_payload_classes := {"delete_query", "update_query", "file_write", "graphql_mutation"}

violate[msg] {
  some cls
  input.payload_class == cls
  not input.approval_ticket
  msg := sprintf("payload class %q denied — ticketed approval required", [cls])
}`;
    case "time_window":
      return `package swarmscan.policy

# Time window — no aggressive scanning 09:00–17:59 local
default allow = true

violate[msg] {
  input.policy_tier == "aggressive"
  input.hour >= 9
  input.hour < 18
  msg := "aggressive profile denied inside business hours (09:00–17:59)"
}`;
    case "target_deny":
      return `package swarmscan.policy

# Target deny — blocklisted hosts never receive probes
default allow = true

blocklist := {"staging.internal", "legacy-payments.corp"}

violate[msg] {
  input.target.host in blocklist
  msg := sprintf("target %q is deny-listed by policy", [input.target.host])
}`;
    default:
      return `package swarmscan.policy

# Data-touching gate — SELECT-only PoC unless a ticketed approval exists
default allow = true

violate[msg] {
  input.agent.safety_class == "data-touching"
  not input.approval_ticket
  input.payload_class != "select_poc"
  msg := "data-touching state aborted — approval ticket required"
}`;
  }
}

/** Renders the first N lines of a policy body as a muted preview. */
export function regoPreview(code: string, lines = 5): string {
  return code
    .split("\n")
    .slice(0, lines)
    .join("\n");
}

export const REGO_HINT =
  "Policies are evaluated per request by the control plane; violations abort agent states and write to the audit ledger.";
