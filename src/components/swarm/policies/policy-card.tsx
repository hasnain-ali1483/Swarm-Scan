"use client";

// ─── Policy card — OPA/Rego policy with enable switch and actions ─────────────

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Pencil, Trash2 } from "lucide-react";
import { cn, timeAgo } from "@/lib/swarm/format";
import type { PolicyItem } from "@/lib/swarm/types";
import { kindBadgeClass, kindChipTitle, kindLabel, regoPreview } from "./policy-kinds";

export function PolicyCard({
  policy,
  index,
  onToggle,
  onEdit,
  onDelete,
  busy,
}: {
  policy: PolicyItem;
  index: number;
  onToggle: (policy: PolicyItem, enabled: boolean) => void;
  onEdit: (policy: PolicyItem) => void;
  onDelete: (policy: PolicyItem) => void;
  busy?: boolean;
}) {
  const switchId = `policy-enabled-${policy.id}`;
  return (
    <article
      className={cn(
        "flex flex-col rounded-lg border bg-card/60 p-4 transition-colors",
        policy.enabled ? "border-zinc-800 hover:border-primary/30" : "border-zinc-800/60 opacity-75 hover:opacity-100"
      )}
      aria-label={`Policy ${policy.name}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate font-mono text-sm font-medium text-zinc-100">{policy.name}</h3>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <Badge
              variant="outline"
              className={cn("px-1.5 text-[10px]", kindBadgeClass(policy.kind))}
              title={kindChipTitle(policy.kind)}
            >
              {kindLabel(policy.kind)}
            </Badge>
            <span className="text-[11px] text-zinc-500">updated {timeAgo(policy.updatedAt)}</span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Label
            htmlFor={switchId}
            className={cn(
              "text-[11px]",
              policy.enabled ? "text-emerald-400" : "text-zinc-500"
            )}
          >
            {policy.enabled ? "enabled" : "disabled"}
          </Label>
          <Switch
            id={switchId}
            checked={policy.enabled}
            disabled={busy}
            onCheckedChange={(checked) => onToggle(policy, checked)}
            aria-label={`${policy.enabled ? "Disable" : "Enable"} policy ${policy.name}`}
          />
        </div>
      </div>

      {/* rego snippet */}
      <pre className="mt-3 max-h-24 flex-1 overflow-hidden rounded-md border border-zinc-800/80 bg-zinc-950/60 p-2.5 font-mono text-[10px] leading-4 text-zinc-400">
        {regoPreview(policy.code, 6)}
        {policy.code.split("\n").length > 6 ? "\n…" : ""}
      </pre>

      <div className="mt-3 flex items-center justify-between border-t border-zinc-800/80 pt-3">
        <span className="font-mono text-[10px] text-zinc-600">
          index {String(index + 1).padStart(2, "0")} · rego
        </span>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onEdit(policy)}
            aria-label={`Edit policy ${policy.name}`}
            className="h-7 gap-1.5 px-2 text-xs text-zinc-400 hover:text-zinc-100"
          >
            <Pencil className="h-3.5 w-3.5" aria-hidden />
            Edit
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onDelete(policy)}
            aria-label={`Delete policy ${policy.name}`}
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
