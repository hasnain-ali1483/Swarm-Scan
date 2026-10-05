"use client";

// ─── Active sessions — live sign-ins with one-click revoke (Task 9-b) ────────

import { motion } from "framer-motion";
import { Globe, LogOut, MonitorSmartphone, Timer } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { AccessSessionItem } from "@/lib/swarm/types";
import { timeAgo } from "@/lib/swarm/format";
import { RoleBadge } from "./access-badges";
import { useAccessMutation } from "./use-access";

export function SessionsSection({ sessions }: { sessions: AccessSessionItem[] }) {
  const mutation = useAccessMutation();

  return (
    <div className="overflow-x-auto swarm-scroll">
      <Table className="min-w-[760px]">
        <TableHeader>
          <TableRow>
            <TableHead className="text-xs font-medium text-muted-foreground">Session</TableHead>
            <TableHead className="text-xs font-medium text-muted-foreground">Method</TableHead>
            <TableHead className="text-xs font-medium text-muted-foreground">Origin</TableHead>
            <TableHead className="text-xs font-medium text-muted-foreground">Activity</TableHead>
            <TableHead className="text-right text-xs font-medium text-muted-foreground">—</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sessions.map((s, i) => (
            <motion.tr
              key={s.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: Math.min(i * 0.04, 0.3), duration: 0.2 }}
              className="border-b transition-colors hover:bg-accent/40"
            >
              <TableCell className="py-3">
                <div className="flex items-center gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-primary/25 bg-primary/10 text-[10px] font-semibold text-primary">
                    {s.userName.split(/\s+/).map((p) => p[0]).join("").slice(0, 2).toUpperCase()}
                  </span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{s.userName}</span>
                      <RoleBadge role={s.role} />
                    </div>
                    <span className="font-mono text-[10px] text-muted-foreground">{s.userEmail}</span>
                  </div>
                </div>
              </TableCell>
              <TableCell className="py-3">
                <span className="inline-flex items-center gap-1.5 text-xs text-zinc-300">
                  <MonitorSmartphone className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                  {s.method}
                </span>
                <div className="font-mono text-[10px] text-muted-foreground">{s.ua}</div>
              </TableCell>
              <TableCell className="py-3">
                <div className="flex flex-col">
                  <span className="inline-flex items-center gap-1.5 font-mono text-xs text-zinc-300">
                    <Globe className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                    {s.ip}
                  </span>
                  <span className="text-[10px] text-muted-foreground">{s.location}</span>
                </div>
              </TableCell>
              <TableCell className="py-3">
                <div className="flex flex-col gap-0.5 text-xs">
                  <span>started {timeAgo(s.startedAt)}</span>
                  <span className="inline-flex items-center gap-1 text-muted-foreground">
                    <Timer className="h-3 w-3" aria-hidden />
                    seen {timeAgo(s.lastSeenAt)} · expires{" "}
                    {new Date(s.expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
              </TableCell>
              <TableCell className="py-2.5 text-right">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={mutation.isPending}
                  onClick={() => mutation.mutate({ action: "session.revoke", id: s.id })}
                  className="h-7 gap-1.5 text-[11px] text-red-400 hover:bg-red-500/10 hover:text-red-400"
                  aria-label={`Revoke session for ${s.userName}`}
                >
                  <LogOut className="h-3.5 w-3.5" aria-hidden />
                  Revoke
                </Button>
              </TableCell>
            </motion.tr>
          ))}
        </TableBody>
      </Table>
      {sessions.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted-foreground">
          No active sessions — everyone signed out.
        </p>
      ) : null}
    </div>
  );
}
