"use client";

// ─── SSO connections — SAML / OIDC / SCIM directory cards (Task 9-b) ─────────

import { motion } from "framer-motion";
import { ArrowLeftRight, BadgeCheck, Fingerprint, RefreshCw, Users2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { SsoConnectionItem } from "@/lib/swarm/types";
import { timeAgo } from "@/lib/swarm/format";
import { cn } from "@/lib/swarm/format";
import { SsoStatusBadge } from "./access-badges";
import { useAccessMutation } from "./use-access";

const KIND_META: Record<SsoConnectionItem["kind"], { label: string; icon: typeof Fingerprint; cls: string }> = {
  saml: { label: "SAML 2.0", icon: BadgeCheck, cls: "border-primary/30 bg-primary/10 text-primary" },
  oidc: { label: "OIDC", icon: Fingerprint, cls: "border-teal-500/30 bg-teal-500/10 text-teal-300" },
  scim: { label: "SCIM v2", icon: ArrowLeftRight, cls: "border-violet-400/30 bg-violet-400/10 text-violet-300" },
};

export function SsoSection({ connections }: { connections: SsoConnectionItem[] }) {
  const mutation = useAccessMutation();

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {connections.map((c, i) => {
        const meta = KIND_META[c.kind];
        const Icon = meta.icon;
        return (
          <motion.div
            key={c.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: Math.min(i * 0.06, 0.3), duration: 0.25 }}
            className={cn(
              "group relative flex flex-col gap-3 rounded-lg border p-4 transition-colors",
              c.status === "connected"
                ? "border-border bg-card/60 hover:border-primary/40"
                : c.status === "pending"
                  ? "border-amber-500/25 bg-amber-500/[0.03] hover:border-amber-500/40"
                  : "border-red-500/25 bg-red-500/[0.03] hover:border-red-500/40"
            )}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2.5 min-w-0">
                <span className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-md border", meta.cls)}>
                  <Icon className="h-4.5 w-4.5" aria-hidden />
                </span>
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium leading-tight">{c.name}</div>
                  <div className="mt-0.5 flex items-center gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground">{c.domain}</span>
                    <span className={cn("rounded border px-1 py-0.5 font-mono text-[9px] uppercase tracking-wider", meta.cls)}>
                      {meta.label}
                    </span>
                  </div>
                </div>
              </div>
              <SsoStatusBadge status={c.status} />
            </div>

            <p className="font-mono text-[10px] leading-relaxed text-muted-foreground break-words" title={c.detail}>
              {c.detail}
            </p>

            <div className="flex items-center justify-between gap-2 border-t border-border/60 pt-2.5">
              <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                <span className="inline-flex items-center gap-1">
                  <Users2 className="h-3 w-3" aria-hidden />
                  {c.userCount} user{c.userCount === 1 ? "" : "s"}
                </span>
                <span className="inline-flex items-center gap-1">
                  <RefreshCw className="h-3 w-3" aria-hidden />
                  {c.lastSyncAt ? `synced ${timeAgo(c.lastSyncAt)}` : "never synced"}
                </span>
              </div>
              <Button
                variant={c.status === "disabled" ? "outline" : "ghost"}
                size="sm"
                disabled={mutation.isPending || c.status === "pending"}
                onClick={() =>
                  mutation.mutate({
                    action: "sso.status",
                    id: c.id,
                    status: c.status === "disabled" ? "connected" : "disabled",
                  })
                }
                className={cn(
                  "h-7 gap-1.5 text-[11px]",
                  c.status === "pending"
                    ? "text-muted-foreground"
                    : c.status === "disabled"
                      ? "text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-400"
                      : "text-red-400 hover:bg-red-500/10 hover:text-red-400"
                )}
                title={
                  c.status === "pending"
                    ? "Pending metadata exchange — approve via API"
                    : c.status === "disabled"
                      ? "Re-enable this identity provider"
                      : "Disable — logins via this IdP will be rejected"
                }
              >
                {c.status === "disabled" ? "Enable" : "Disable"}
              </Button>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
