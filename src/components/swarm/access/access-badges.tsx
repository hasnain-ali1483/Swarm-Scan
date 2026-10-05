"use client";

// ─── Access control — shared badges (Task 9-b) ──────────────────────────────

import { Badge } from "@/components/ui/badge";
import { KeyRound, Lock, ShieldCheck, ShieldOff, UserCheck } from "lucide-react";
import type { AccessRole, AccessUser, SsoConnectionItem } from "@/lib/swarm/types";
import { cn } from "@/lib/swarm/format";

const ROLE_STYLES: Record<AccessRole, string> = {
  owner: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  admin: "border-primary/40 bg-primary/10 text-primary",
  operator: "border-teal-500/40 bg-teal-500/10 text-teal-300",
  auditor: "border-violet-400/40 bg-violet-400/10 text-violet-300",
  viewer: "border-zinc-500/40 bg-zinc-500/10 text-zinc-300",
};

const ROLE_HINT: Record<AccessRole, string> = {
  owner: "Full tenancy control — 20/20 permissions",
  admin: "Platform administration — except tenancy + monitoring ops",
  operator: "Runs scans, triages findings, engages kill switch",
  auditor: "Read-only evidence review + chain verification",
  viewer: "Dashboard-only — findings:read",
};

export function RoleBadge({ role, className }: { role: AccessRole; className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn("gap-1 font-medium capitalize", ROLE_STYLES[role], className)}
      title={ROLE_HINT[role]}
    >
      {role === "owner" ? <ShieldCheck className="h-3 w-3" aria-hidden /> : null}
      {role}
    </Badge>
  );
}

export function UserStatusBadge({ status }: { status: AccessUser["status"] }) {
  return status === "active" ? (
    <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
      <UserCheck className="h-3 w-3" aria-hidden />
      active
    </Badge>
  ) : (
    <Badge variant="outline" className="gap-1 border-red-500/40 bg-red-500/10 text-red-300">
      <ShieldOff className="h-3 w-3" aria-hidden />
      suspended
    </Badge>
  );
}

export function MfaBadge({ mfa }: { mfa: boolean }) {
  return mfa ? (
    <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/5 text-emerald-400" title="MFA enforced">
      MFA
    </Badge>
  ) : (
    <Badge
      variant="outline"
      className="border-amber-500/30 bg-amber-500/5 text-amber-400"
      title="No second factor — enforce via SSO policy"
    >
      no MFA
    </Badge>
  );
}

export function ProviderBadge({ provider }: { provider: string }) {
  const map: Record<string, { label: string; cls: string; icon: boolean }> = {
    "okta-saml": { label: "Okta · SAML", cls: "border-primary/30 bg-primary/5 text-primary", icon: false },
    "auth0-oidc": { label: "Auth0 · OIDC", cls: "border-teal-500/30 bg-teal-500/5 text-teal-300", icon: false },
    scim: { label: "SCIM", cls: "border-violet-400/30 bg-violet-400/5 text-violet-300", icon: false },
    local: { label: "Password", cls: "border-zinc-500/30 bg-zinc-500/5 text-zinc-400", icon: false },
  };
  const m = map[provider] ?? { label: provider, cls: "border-zinc-500/30 bg-zinc-500/5 text-zinc-400", icon: false };
  return (
    <Badge variant="outline" className={cn("font-mono text-[10px]", m.cls)}>
      {m.icon ? <KeyRound className="h-3 w-3" aria-hidden /> : null}
      {m.label}
    </Badge>
  );
}

export function SsoStatusBadge({ status }: { status: SsoConnectionItem["status"] }) {
  if (status === "connected") {
    return (
      <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 swarm-pulse" aria-hidden />
        connected
      </Badge>
    );
  }
  if (status === "pending") {
    return (
      <Badge variant="outline" className="gap-1 border-amber-500/40 bg-amber-500/10 text-amber-300">
        <Lock className="h-3 w-3" aria-hidden />
        pending
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="gap-1 border-red-500/40 bg-red-500/10 text-red-300">
      <ShieldOff className="h-3 w-3" aria-hidden />
      disabled
    </Badge>
  );
}
