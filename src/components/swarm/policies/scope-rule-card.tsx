"use client";

// ─── Scope firewall rule card — CIDRs, mode badge, enforcement switch ─────────

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Pencil, Trash2 } from "lucide-react";
import { cn } from "@/lib/swarm/format";
import type { ScopeRuleItem } from "@/lib/swarm/types";

export function ScopeRuleCard({
  rule,
  onToggle,
  onEdit,
  onDelete,
  busy,
}: {
  rule: ScopeRuleItem;
  onToggle: (rule: ScopeRuleItem, enforced: boolean) => void;
  onEdit: (rule: ScopeRuleItem) => void;
  onDelete: (rule: ScopeRuleItem) => void;
  busy?: boolean;
}) {
  const switchId = `scope-enforced-${rule.id}`;
  return (
    <article
      className="flex flex-col rounded-lg border border-zinc-800 bg-card/60 p-4 transition-colors hover:border-primary/30"
      aria-label={`Scope rule ${rule.name}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate font-mono text-sm font-medium text-zinc-100">{rule.name}</h3>
          <div className="mt-1.5 flex items-center gap-2">
            <Badge
              variant="outline"
              className={cn(
                "px-1.5 text-[10px]",
                rule.mode === "allowlist"
                  ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/40"
                  : "bg-red-500/15 text-red-400 border-red-500/40"
              )}
            >
              {rule.mode}
            </Badge>
            <span className="font-mono text-[10px] text-zinc-500">
              {rule.cidrs.length} CIDR{rule.cidrs.length === 1 ? "" : "s"}
            </span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Label
            htmlFor={switchId}
            className={cn("text-[11px]", rule.enforced ? "text-emerald-400" : "text-zinc-500")}
          >
            {rule.enforced ? "enforced" : "advisory"}
          </Label>
          <Switch
            id={switchId}
            checked={rule.enforced}
            disabled={busy}
            onCheckedChange={(checked) => onToggle(rule, checked)}
            aria-label={`${rule.enforced ? "Disable" : "Enable"} enforcement for ${rule.name}`}
          />
        </div>
      </div>

      {/* CIDR chips */}
      <div className="mt-3 flex flex-wrap gap-1.5" aria-label="Rule CIDRs">
        {rule.cidrs.map((cidr) => (
          <span
            key={cidr}
            className={cn(
              "rounded-sm border px-1.5 py-px font-mono text-[10px]",
              rule.mode === "allowlist"
                ? "border-emerald-500/25 bg-emerald-500/8 text-emerald-300"
                : "border-red-500/25 bg-red-500/8 text-red-300"
            )}
          >
            {cidr}
          </span>
        ))}
      </div>

      <div className="mt-3 flex items-center justify-between border-t border-zinc-800/80 pt-3">
        <span className="text-[10px] text-zinc-600">
          {rule.enforced ? "kernel-enforced · eBPF/LSM" : "app-layer advisory only"}
        </span>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onEdit(rule)}
            aria-label={`Edit scope rule ${rule.name}`}
            className="h-7 gap-1.5 px-2 text-xs text-zinc-400 hover:text-zinc-100"
          >
            <Pencil className="h-3.5 w-3.5" aria-hidden />
            Edit
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onDelete(rule)}
            aria-label={`Delete scope rule ${rule.name}`}
            className="h-7 gap-1.5 px-2 text-xs text-zinc-400 hover:bg-destructive/10 hover:text-destructive"
          >
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
            Delete
          </Button>
        </div>
      </div>
    </article>
  );
}
