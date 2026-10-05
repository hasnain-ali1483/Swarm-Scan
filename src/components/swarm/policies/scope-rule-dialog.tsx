"use client";

// ─── Scope rule create/edit dialog — CIDR editor with live chips + validation ─

import { useMemo, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Loader2, Network } from "lucide-react";
import { cn } from "@/lib/swarm/format";
import type { ScopeRuleItem } from "@/lib/swarm/types";

export interface ScopeDraft {
  name: string;
  mode: "allowlist" | "denylist";
  cidrs: string[];
  enforced: boolean;
}

function parseCidrs(text: string): { valid: string[]; invalid: string[] } {
  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  const valid: string[] = [];
  const invalid: string[] = [];
  for (const line of lines) {
    if (line.includes("/")) valid.push(line);
    else invalid.push(line);
  }
  return { valid, invalid };
}

export function ScopeRuleDialog({
  open,
  onOpenChange,
  editing,
  onSubmit,
  submitting,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: ScopeRuleItem | null;
  onSubmit: (draft: ScopeDraft) => void;
  submitting: boolean;
}) {
  // Form state is initialized from `editing` — the parent remounts this dialog
  // (key={session}) on every open, so useState initializers act as hydration.
  const [name, setName] = useState(editing?.name ?? "");
  const [mode, setMode] = useState<"allowlist" | "denylist">(editing?.mode ?? "allowlist");
  const [cidrsText, setCidrsText] = useState(editing?.cidrs.join("\n") ?? "");
  const [enforced, setEnforced] = useState(editing?.enforced ?? true);
  const [touched, setTouched] = useState(false);

  const { valid, invalid } = useMemo(() => parseCidrs(cidrsText), [cidrsText]);
  const nameError = touched && !name.trim() ? "Rule name is required" : null;
  const cidrsError =
    touched && valid.length === 0 && invalid.length === 0
      ? "At least one CIDR is required"
      : invalid.length > 0
        ? `Not a CIDR (missing "/"): ${invalid.slice(0, 3).join(", ")}${invalid.length > 3 ? "…" : ""}`
        : null;

  const submit = () => {
    setTouched(true);
    if (!name.trim() || valid.length === 0 || invalid.length > 0) return;
    onSubmit({ name: name.trim(), mode, cidrs: valid, enforced });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-xl overflow-y-auto swarm-scroll bg-zinc-950/95">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit scope rule" : "New scope rule"}</DialogTitle>
          <DialogDescription>
            Rules are compiled into eBPF/LSM filters inside each worker microVM.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="scope-name">Name</Label>
            <Input
              id="scope-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. corp-egress-allowlist"
              aria-invalid={!!nameError}
              className="font-mono text-xs"
            />
            {nameError && <p className="text-[11px] text-destructive">{nameError}</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="scope-mode">Mode</Label>
            <Select
              value={mode}
              onValueChange={(v) => setMode(v as "allowlist" | "denylist")}
            >
              <SelectTrigger id="scope-mode" className="font-mono text-xs" aria-label="Scope mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="allowlist" className="font-mono text-xs">
                  allowlist
                </SelectItem>
                <SelectItem value="denylist" className="font-mono text-xs">
                  denylist
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2">
          <div>
            <Label htmlFor="scope-enforced" className="text-xs">
              Enforced
            </Label>
            <p className="text-[11px] text-zinc-500">
              Kernel-level enforcement — drop packets at the socket layer.
            </p>
          </div>
          <Switch
            id="scope-enforced"
            checked={enforced}
            onCheckedChange={setEnforced}
            aria-label="Toggle kernel enforcement"
          />
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="scope-cidrs">CIDRs — one per line</Label>
          <textarea
            id="scope-cidrs"
            value={cidrsText}
            onChange={(e) => setCidrsText(e.target.value)}
            spellCheck={false}
            aria-invalid={!!cidrsError}
            aria-describedby="scope-cidrs-preview"
            className={cn(
              "min-h-[120px] w-full resize-y rounded-md border bg-zinc-950/60 p-3 font-mono text-xs leading-relaxed text-zinc-200 shadow-sm outline-none transition-colors placeholder:text-zinc-600 focus-visible:ring-1 focus-visible:ring-primary/50",
              cidrsError ? "border-destructive/60" : "border-zinc-800 focus-visible:border-primary/40"
            )}
            placeholder={"10.0.0.0/8\n192.168.1.0/24\n2001:db8::/32"}
          />
          {cidrsError && <p className="text-[11px] text-destructive">{cidrsError}</p>}
          {/* live preview chips */}
          <div
            id="scope-cidrs-preview"
            className="flex flex-wrap items-center gap-1.5 rounded-md border border-zinc-800/70 bg-zinc-900/40 p-2"
            aria-label="CIDR preview"
          >
            <Network className="h-3.5 w-3.5 text-primary" aria-hidden />
            {valid.length === 0 && invalid.length === 0 && (
              <span className="text-[11px] text-zinc-600">no CIDRs yet</span>
            )}
            {valid.map((cidr) => (
              <span
                key={cidr}
                className={cn(
                  "rounded-sm border px-1.5 py-px font-mono text-[10px]",
                  mode === "allowlist"
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                    : "border-red-500/30 bg-red-500/10 text-red-300"
                )}
              >
                {cidr}
              </span>
            ))}
            {invalid.map((cidr) => (
              <span
                key={cidr}
                className="rounded-sm border border-destructive/50 bg-destructive/10 px-1.5 py-px font-mono text-[10px] text-destructive line-through"
                title="Missing '/' — not a valid CIDR"
              >
                {cidr}
              </span>
            ))}
            <span className="ml-auto font-mono text-[10px] text-zinc-600">
              {valid.length} valid
            </span>
          </div>
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={submitting} className="gap-2">
            {submitting && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />}
            {editing ? "Save rule" : "Create rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
