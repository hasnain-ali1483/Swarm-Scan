"use client";

// ─── Permission matrix — 20 permissions × 5 roles (Tasks 9-b + 11 + 13) ────────

import { Fragment } from "react";
import { Check, Minus } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ACCESS_ROLES, PERMISSION_CATALOG, roleCan } from "@/lib/swarm/access-roles";
import type { AccessRole } from "@/lib/swarm/types";
import { cn } from "@/lib/swarm/format";

const GROUPS = ["Scans & Execution", "Findings & Evidence", "Governance", "Registry & Quality", "Access & Tenancy", "Output", "Fleet Topology"];

export function RoleMatrix({ actingRole }: { actingRole: AccessRole }) {
  return (
    <div className="overflow-x-auto swarm-scroll">
      <Table className="min-w-[720px]">
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-[38%] text-xs font-medium text-muted-foreground">Permission</TableHead>
            {ACCESS_ROLES.map((r) => (
              <TableHead
                key={r.key}
                className={cn(
                  "h-10 text-center text-[11px] font-semibold capitalize",
                  r.key === actingRole ? "text-primary" : "text-muted-foreground"
                )}
                title={r.description}
              >
                {r.key === actingRole ? (
                  <span className="inline-flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden />
                    {r.key}
                  </span>
                ) : (
                  r.key
                )}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {GROUPS.map((group) => (
            <Fragment key={group}>
              <TableRow className="hover:bg-transparent">
                <TableCell
                  colSpan={6}
                  className="border-t border-border/60 bg-card/40 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground"
                >
                  {group}
                </TableCell>
              </TableRow>
              {PERMISSION_CATALOG.filter((p) => p.group === group).map((p) => (
                <TableRow
                  key={p.key}
                  className={cn(
                    "transition-colors",
                    p.roles.includes(actingRole) ? "bg-primary/[0.03]" : undefined,
                    "hover:bg-accent/40"
                  )}
                >
                  <TableCell className="py-2.5">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-xs font-medium">{p.label}</span>
                      <code className="font-mono text-[10px] text-muted-foreground">{p.key}</code>
                    </div>
                    <span className="sr-only">{p.description}</span>
                  </TableCell>
                  {ACCESS_ROLES.map((r) => {
                    const granted = roleCan(r.key, p.key);
                    return (
                      <TableCell key={r.key} className="py-2.5 text-center" title={granted ? `${r.key} can ${p.label.toLowerCase()}` : "not granted"}>
                        {granted ? (
                          <span
                            className={cn(
                              "inline-flex h-5 w-5 items-center justify-center rounded-sm",
                              r.key === actingRole
                                ? "bg-primary/20 text-primary"
                                : "bg-emerald-500/10 text-emerald-400"
                            )}
                          >
                            <Check className="h-3.5 w-3.5" aria-hidden />
                            <span className="sr-only">granted</span>
                          </span>
                        ) : (
                          <span className="inline-flex h-5 w-5 items-center justify-center">
                            <Minus className="h-3.5 w-3.5 text-zinc-600" aria-hidden />
                            <span className="sr-only">not granted</span>
                          </span>
                        )}
                      </TableCell>
                    );
                  })}
                </TableRow>
              ))}
            </Fragment>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
