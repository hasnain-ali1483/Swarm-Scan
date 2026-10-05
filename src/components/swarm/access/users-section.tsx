"use client";

// ─── Users directory — role changes, suspend/reactivate (Task 9-b) ──────────

import { useState } from "react";
import { Ban, Check, RotateCcw, UserRound } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { AccessResponse, AccessRole, AccessUser } from "@/lib/swarm/types";
import { ACCESS_ROLES } from "@/lib/swarm/access-roles";
import { cn, timeAgo } from "@/lib/swarm/format";
import { MfaBadge, ProviderBadge, RoleBadge, UserStatusBadge } from "./access-badges";
import { useAccessMutation } from "./use-access";
import { useSwarmUi } from "@/lib/swarm/ui-store";

const AVATAR_TONES = [
  "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  "bg-teal-500/15 text-teal-300 border-teal-500/30",
  "bg-amber-500/15 text-amber-300 border-amber-500/30",
  "bg-rose-500/15 text-rose-300 border-rose-500/30",
  "bg-violet-400/15 text-violet-300 border-violet-400/30",
  "bg-orange-500/15 text-orange-300 border-orange-500/30",
];

function avatarTone(email: string): string {
  let h = 0;
  for (const c of email) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return AVATAR_TONES[h % AVATAR_TONES.length];
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? "")
    .join("");
}

export function UsersSection({ data }: { data: AccessResponse }) {
  const mutation = useAccessMutation();
  const actingRole = useSwarmUi((s) => s.actingRole);
  const [busyId, setBusyId] = useState<string | null>(null);

  const act = async (action: Parameters<typeof mutation.mutateAsync>[0], userId: string) => {
    setBusyId(userId);
    try {
      await mutation.mutateAsync(action);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="overflow-x-auto swarm-scroll">
      <Table className="min-w-[860px]">
        <TableHeader>
          <TableRow>
            <TableHead className="text-xs font-medium text-muted-foreground">Member</TableHead>
            <TableHead className="text-xs font-medium text-muted-foreground">Role</TableHead>
            <TableHead className="text-xs font-medium text-muted-foreground">Team</TableHead>
            <TableHead className="text-xs font-medium text-muted-foreground">Auth</TableHead>
            <TableHead className="text-xs font-medium text-muted-foreground">Last login</TableHead>
            <TableHead className="text-right text-xs font-medium text-muted-foreground">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.users.map((u: AccessUser, i: number) => {
            const busy = busyId === u.id;
            return (
              <TableRow
                key={u.id}
                className={cn(
                  "transition-colors hover:bg-accent/40",
                  u.status === "suspended" && "bg-red-500/[0.03] opacity-75"
                )}
              >
                <TableCell className="py-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={cn(
                        "flex h-8 w-8 shrink-0 items-center justify-center rounded-full border font-semibold text-xs",
                        avatarTone(u.email + i)
                      )}
                      aria-hidden
                    >
                      {initials(u.name)}
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-sm font-medium">{u.name}</span>
                        {u.name.includes("svc") ? (
                          <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground border rounded px-1 py-0.5">
                            service
                          </span>
                        ) : null}
                      </div>
                      <div className="truncate font-mono text-[11px] text-muted-foreground">{u.email}</div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="py-3">
                  <div className="flex items-center gap-2">
                    <RoleBadge role={u.role} className="hidden sm:inline-flex" />
                    <Select
                      value={u.role}
                      disabled={busy || mutation.isPending}
                      onValueChange={(role) =>
                        act({ action: "user.role", id: u.id, role: role as AccessRole, actor: actingRole }, u.id)
                      }
                    >
                      <SelectTrigger
                        className="h-7 w-[120px] text-xs"
                        aria-label={`Change role for ${u.name}`}
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ACCESS_ROLES.map((r) => (
                          <SelectItem key={r.key} value={r.key} className="text-xs capitalize">
                            {r.key}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </TableCell>
                <TableCell className="py-3 text-xs text-zinc-300">{u.team}</TableCell>
                <TableCell className="py-3">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <ProviderBadge provider={u.provider} />
                    <MfaBadge mfa={u.mfa} />
                  </div>
                </TableCell>
                <TableCell className="py-3">
                  <div className="flex flex-col">
                    <span className="text-xs">{u.lastLoginAt ? timeAgo(u.lastLoginAt) : "—"}</span>
                    <UserStatusBadge status={u.status} />
                  </div>
                </TableCell>
                <TableCell className="py-3 text-right">
                  {u.status === "active" ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onClick={() => act({ action: "user.status", id: u.id, status: "suspended" }, u.id)}
                      className="h-7 gap-1.5 text-[11px] text-red-400 hover:bg-red-500/10 hover:text-red-400"
                      title="Suspend — revokes all sessions immediately"
                    >
                      <Ban className="h-3.5 w-3.5" aria-hidden />
                      Suspend
                    </Button>
                  ) : (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onClick={() => act({ action: "user.status", id: u.id, status: "active" }, u.id)}
                      className="h-7 gap-1.5 text-[11px] text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-400"
                    >
                      <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                      Reactivate
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <p className="mt-3 flex items-center gap-2 text-[11px] text-muted-foreground">
        <UserRound className="h-3.5 w-3.5" aria-hidden />
        Suspending a member revokes every active session immediately and blocks new logins (SCIM
        deprovision semantics). The last active owner cannot be demoted or suspended.
      </p>
    </div>
  );
}
