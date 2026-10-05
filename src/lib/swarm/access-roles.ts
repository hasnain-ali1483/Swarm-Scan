// ─── Access control — RBAC role catalog (Task 9-b) ──────────────────────────
// Environment-agnostic (pure data, no React): shared by the Access view, the
// header role badge, the permission gating on the global Kill Switch / New
// Scan wizard (client), and the server route's validation. Deliberately has
// NO "use client"/"use server" directive so both planes can import it.

import type { AccessRole, PermissionRow } from "@/lib/swarm/types";

export const ACCESS_ROLES: {
  key: AccessRole;
  label: string;
  description: string;
  grant: string;
}[] = [
  {
    key: "owner",
    label: "Owner",
    description: "Full tenancy control — can transfer/delete the organization and manage billing.",
    grant: "All 21 permissions · tenancy:manage & oracles:destructive are owner-exclusive",
  },
  {
    key: "admin",
    label: "Admin",
    description: "Platform administration — users, SSO, policies, agent registry, integrations.",
    grant: "Everything except tenancy:manage and monitoring:manage",
  },
  {
    key: "operator",
    label: "Operator",
    description: "Runs scans and triages findings — launch, kill, re-verify, export reports.",
    grant: "Scans, findings verify, kill switch, benchmark runs, exports, monitoring",
  },
  {
    key: "auditor",
    label: "Auditor",
    description: "Read-only evidence review — WORM ledger, chain verification, compliance exports.",
    grant: "Read + chains:verify + ledger + reports. No scan launch.",
  },
  {
    key: "viewer",
    label: "Viewer",
    description: "Dashboard-only access for stakeholders — no mutations of any kind.",
    grant: "findings:read only",
  },
];

// Permission matrix — grouped for the UI, flat for roleCan() lookups.
export const PERMISSION_CATALOG: (PermissionRow & { group: string })[] = [
  // Scans & execution
  {
    group: "Scans & Execution",
    key: "scans:launch",
    label: "Launch scans",
    description: "Start new scans via the wizard or API",
    roles: ["owner", "admin", "operator"],
  },
  {
    group: "Scans & Execution",
    key: "scans:kill",
    label: "Kill individual scans",
    description: "Halt one scan while preserving its evidence",
    roles: ["owner", "admin", "operator"],
  },
  {
    group: "Scans & Execution",
    key: "oracles:destructive",
    label: "Authorize destructive oracles",
    description:
      "Permit the intrusive/destructive-class probes (data-touching, RCE, exfil — the aggressive tier). OWNER-EXCLUSIVE: not even Admin can hold or grant this.",
    roles: ["owner"],
  },
  {
    group: "Scans & Execution",
    key: "killswitch:engage",
    label: "Engage global kill switch",
    description: "SIGKILL all workers platform-wide (< 500 ms)",
    roles: ["owner", "admin", "operator"],
  },
  {
    group: "Scans & Execution",
    key: "monitoring:manage",
    label: "Manage continuous monitoring",
    description: "Pause/resume profiles, acknowledge alerts",
    roles: ["owner", "operator"],
  },
  // Findings & evidence
  {
    group: "Findings & Evidence",
    key: "findings:read",
    label: "Read findings",
    description: "View findings, confidence worksheets, PoCs",
    roles: ["owner", "admin", "operator", "auditor", "viewer"],
  },
  {
    group: "Findings & Evidence",
    key: "findings:verify",
    label: "Re-verify findings",
    description: "Trigger re-verification (appends ledger evidence)",
    roles: ["owner", "admin", "operator"],
  },
  {
    group: "Findings & Evidence",
    key: "chains:verify",
    label: "Verify attack chains",
    description: "Advance chain step-verification with approvals",
    roles: ["owner", "admin", "operator", "auditor"],
  },
  {
    group: "Findings & Evidence",
    key: "ledger:read",
    label: "Read WORM ledger",
    description: "Audit the hash-chained evidence trail",
    roles: ["owner", "admin", "operator", "auditor"],
  },
  // Governance
  {
    group: "Governance",
    key: "policies:write",
    label: "Edit OPA policies",
    description: "Create/modify Rego policies and tiers",
    roles: ["owner", "admin"],
  },
  {
    group: "Governance",
    key: "scope:write",
    label: "Edit scope firewall rules",
    description: "Modify eBPF-enforced CIDR allow/deny rules",
    roles: ["owner", "admin"],
  },
  // Registry & quality
  {
    group: "Registry & Quality",
    key: "agents:publish",
    label: "Publish agent releases",
    description: "Promote WASM bundles to the registry (CI-gated)",
    roles: ["owner", "admin"],
  },
  {
    group: "Registry & Quality",
    key: "signing:verify",
    label: "Verify bundle signatures",
    description: "Run Sigstore/SLSA verification on agent bundles",
    roles: ["owner", "admin", "operator", "auditor"],
  },
  {
    group: "Registry & Quality",
    key: "benchmark:run",
    label: "Run benchmark suite",
    description: "Execute the 500-case FN regression corpus",
    roles: ["owner", "admin", "operator", "auditor"],
  },
  // Access & tenancy
  {
    group: "Access & Tenancy",
    key: "users:manage",
    label: "Manage users & roles",
    description: "Invite, suspend, change roles",
    roles: ["owner", "admin"],
  },
  {
    group: "Access & Tenancy",
    key: "sso:manage",
    label: "Manage SSO connections",
    description: "Configure SAML/OIDC/SCIM directories",
    roles: ["owner", "admin"],
  },
  {
    group: "Access & Tenancy",
    key: "keys:manage",
    label: "Manage API keys",
    description: "Create/revoke scoped machine credentials",
    roles: ["owner", "admin"],
  },
  {
    group: "Access & Tenancy",
    key: "tenancy:manage",
    label: "Manage tenancy",
    description: "Transfer or delete the organization, billing",
    roles: ["owner"],
  },
  // Output
  {
    group: "Output",
    key: "reports:export",
    label: "Export reports",
    description: "Executive, technical, SARIF 2.1 downloads",
    roles: ["owner", "admin", "operator", "auditor"],
  },
  {
    group: "Output",
    key: "scheduler:manage",
    label: "Manage export scheduler",
    description: "Create/pause scheduled compliance + report deliveries",
    roles: ["owner", "admin"],
  },
  // Fleet topology
  {
    group: "Fleet Topology",
    key: "shards:manage",
    label: "Reshard the worker fleet",
    description: "Add/remove workers and trigger ring rebalances",
    roles: ["owner", "admin", "operator"],
  },
];

const GRANTS: Record<string, Set<AccessRole>> = Object.fromEntries(
  PERMISSION_CATALOG.map((p) => [p.key, new Set(p.roles)])
);

/** True when `role` is granted `permission` (e.g. roleCan("viewer", "scans:launch")). */
export function roleCan(role: AccessRole, permission: string): boolean {
  return GRANTS[permission]?.has(role) ?? false;
}

/**
 * The destructive-oracle class (data-touching / RCE / exfil — the aggressive
 * policy tier) is OWNER-EXCLUSIVE. Admin and below can never authorize it, and
 * admin cannot grant the Owner role that would confer it (see applyAccessAction).
 */
export const DESTRUCTIVE_PERMISSION = "oracles:destructive";
export function canAuthorizeDestructive(role: AccessRole): boolean {
  return roleCan(role, DESTRUCTIVE_PERMISSION);
}

export function roleLabel(role: string): string {
  return ACCESS_ROLES.find((r) => r.key === role)?.label ?? role;
}

export const API_KEY_SCOPES: { key: string; label: string; hint: string }[] = [
  { key: "scans:read", label: "scans:read", hint: "List scans and live agent FSM state" },
  { key: "scans:launch", label: "scans:launch", hint: "Start scans from CI pipelines" },
  { key: "findings:read", label: "findings:read", hint: "Read findings + evidence chains" },
  { key: "reports:export", label: "reports:export", hint: "Pull SARIF/executive reports" },
  { key: "ledger:read", label: "ledger:read", hint: "Verify WORM chain head" },
];
