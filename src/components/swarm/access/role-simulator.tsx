"use client";

// ─── Role simulator — "acting as" with real permission gating (Task 9-b) ────
// This is a live enforcement demo: switching the acting role re-gates the
// global Kill Switch (header) and the New Scan wizard (Scans view) instantly,
// and the tiles below mirror the same roleCan() checks with lock affordances.

import { motion } from "framer-motion";
import { Lock, Radar, Siren, ShieldCheck, Unlock } from "lucide-react";
import { ACCESS_ROLES, PERMISSION_CATALOG, roleCan } from "@/lib/swarm/access-roles";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import type { AccessRole } from "@/lib/swarm/types";
import { cn } from "@/lib/swarm/format";

const DEMO_PERMISSIONS = [
  { key: "scans:launch", label: "Launch scans", icon: Radar, where: "Scans view" },
  { key: "killswitch:engage", label: "Kill switch", icon: Siren, where: "Header" },
  { key: "policies:write", label: "Edit policies", icon: ShieldCheck, where: "Policies view" },
];

export function RoleSimulator() {
  const actingRole = useSwarmUi((s) => s.actingRole);
  const setActingRole = useSwarmUi((s) => s.setActingRole);
  const setView = useSwarmUi((s) => s.setView);

  const granted = PERMISSION_CATALOG.filter((p) => p.roles.includes(actingRole)).length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] leading-relaxed text-muted-foreground">
          Switch the acting role to see enforcement live — the global Kill Switch and the New Scan
          wizard re-gate instantly across the whole app.
        </p>
        <span className="font-mono text-[10px] text-muted-foreground">
          {granted}/{PERMISSION_CATALOG.length} permissions
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5" role="radiogroup" aria-label="Acting role">
        {ACCESS_ROLES.map((r) => {
          const active = actingRole === r.key;
          return (
            <button
              key={r.key}
              role="radio"
              aria-checked={active}
              onClick={() => setActingRole(r.key as AccessRole)}
              title={r.description}
              className={cn(
                "group flex flex-col items-center gap-1 rounded-lg border px-2 py-3 transition-all",
                active
                  ? "border-primary/50 bg-primary/10 shadow-[0_0_16px_-6px] shadow-primary/40"
                  : "border-border bg-card/40 hover:border-primary/25 hover:bg-accent/40"
              )}
            >
              <span
                className={cn(
                  "text-sm font-semibold capitalize",
                  active ? "text-primary" : "text-foreground/80 group-hover:text-foreground"
                )}
              >
                {r.key}
              </span>
              <span className="font-mono text-[9px] text-muted-foreground">
                {PERMISSION_CATALOG.filter((p) => p.roles.includes(r.key)).length} perms
              </span>
            </button>
          );
        })}
      </div>

      <div className="grid gap-2 sm:grid-cols-3">
        {DEMO_PERMISSIONS.map((d, i) => {
          const allowed = roleCan(actingRole, d.key);
          const Icon = d.icon;
          return (
            <motion.div
              key={d.key}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05, duration: 0.2 }}
              className={cn(
                "flex items-center gap-3 rounded-lg border px-3 py-2.5",
                allowed ? "border-emerald-500/25 bg-emerald-500/[0.04]" : "border-border bg-card/30"
              )}
            >
              <span
                className={cn(
                  "flex h-8 w-8 shrink-0 items-center justify-center rounded-md border",
                  allowed
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-zinc-600/40 bg-zinc-700/20 text-zinc-500"
                )}
              >
                <Icon className="h-4 w-4" aria-hidden />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-xs font-medium leading-tight">{d.label}</div>
                <div className="text-[10px] text-muted-foreground">{d.where}</div>
              </div>
              {allowed ? (
                <span className="inline-flex items-center gap-1 text-[10px] font-medium text-emerald-400">
                  <Unlock className="h-3 w-3" aria-hidden />
                  allowed
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[10px] font-medium text-zinc-500">
                  <Lock className="h-3 w-3" aria-hidden />
                  denied
                </span>
              )}
            </motion.div>
          );
        })}
      </div>

      {actingRole !== "owner" ? (
        <button
          onClick={() => setView("scans")}
          className="w-full rounded-md border border-dashed border-border px-3 py-2 text-[11px] text-muted-foreground transition-colors hover:border-primary/30 hover:text-foreground"
        >
          Try the Scans view {actingRole === "auditor" || actingRole === "viewer" ? "— the New Scan button is locked for " + actingRole : "as " + actingRole} →
        </button>
      ) : null}
    </div>
  );
}

/** Compact header pill: shows the acting role, click jumps to Access Control. */
export function ActingRolePill() {
  const actingRole = useSwarmUi((s) => s.actingRole);
  const setView = useSwarmUi((s) => s.setView);
  const gated = !roleCan(actingRole, "killswitch:engage");

  return (
    <button
      onClick={() => setView("access")}
      title={`Acting as ${actingRole} — click to change (Access Control)`}
      aria-label={`Acting role: ${actingRole}. Open Access Control to change.`}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors",
        gated
          ? "border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/15"
          : "border-border bg-card/60 text-muted-foreground hover:text-foreground"
      )}
    >
      {gated ? <Lock className="h-3 w-3" aria-hidden /> : <ShieldCheck className="h-3 w-3" aria-hidden />}
      <span className="capitalize">{actingRole}</span>
    </button>
  );
}
