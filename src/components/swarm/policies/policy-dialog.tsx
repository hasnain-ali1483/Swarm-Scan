"use client";

// ─── Policy create/edit dialog — Rego editor with live highlighted preview ────

import { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
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
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/swarm/format";
import type { PolicyItem } from "@/lib/swarm/types";
import {
  POLICY_KINDS,
  REGO_HINT,
  defaultRegoForKind,
} from "@/components/swarm/policies/policy-kinds";

export interface PolicyDraft {
  name: string;
  kind: string;
  code: string;
  enabled: boolean;
}

export function PolicyDialog({
  open,
  onOpenChange,
  editing,
  onSubmit,
  submitting,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  editing: PolicyItem | null;
  onSubmit: (draft: PolicyDraft) => void;
  submitting: boolean;
}) {
  // Form state is initialized from `editing` — the parent remounts this dialog
  // (key={session}) on every open, so useState initializers act as hydration.
  const [name, setName] = useState(editing?.name ?? "");
  const [kind, setKind] = useState<string>(editing?.kind ?? "rate_limit");
  const [code, setCode] = useState(
    editing?.code ?? defaultRegoForKind(editing?.kind ?? "rate_limit")
  );
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [touched, setTouched] = useState(false);

  const nameError = touched && !name.trim() ? "Policy name is required" : null;
  const codeError = touched && !code.trim() ? "Rego module cannot be empty" : null;

  const onKindChange = (next: string) => {
    setKind(next);
    // Fresh template only when the body is untouched or still a pristine template.
    if (!editing && (code.trim() === "" || Object.values(POLICY_KINDS).some((k) => code === defaultRegoForKind(k)))) {
      setCode(defaultRegoForKind(next));
    }
  };

  const submit = () => {
    setTouched(true);
    if (!name.trim() || !code.trim()) return;
    onSubmit({ name: name.trim(), kind, code, enabled });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto swarm-scroll bg-zinc-950/95">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit policy" : "New policy"}</DialogTitle>
          <DialogDescription>
            Policy-as-code evaluated by the OPA sidecar on every agent request.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="policy-name">Name</Label>
            <Input
              id="policy-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. business-hours-only"
              aria-invalid={!!nameError}
              className="font-mono text-xs"
            />
            {nameError && <p className="text-[11px] text-destructive">{nameError}</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="policy-kind">Kind</Label>
            <Select value={kind} onValueChange={onKindChange}>
              <SelectTrigger id="policy-kind" className="font-mono text-xs" aria-label="Policy kind">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {POLICY_KINDS.map((k) => (
                  <SelectItem key={k} value={k} className="font-mono text-xs">
                    {k}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-900/40 px-3 py-2">
          <div>
            <Label htmlFor="policy-enabled" className="text-xs">
              Enabled
            </Label>
            <p className="text-[11px] text-zinc-500">
              Disabled policies are kept in version control but skip evaluation.
            </p>
          </div>
          <Switch
            id="policy-enabled"
            checked={enabled}
            onCheckedChange={setEnabled}
            aria-label="Toggle policy enabled"
          />
        </div>

        {/* Rego editor */}
        <div className="space-y-1.5">
          <Label htmlFor="policy-code" className="font-mono text-xs">
            policy.rego
          </Label>
          <textarea
            id="policy-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            spellCheck={false}
            aria-invalid={!!codeError}
            aria-describedby="policy-code-hint"
            className={cn(
              "min-h-[280px] w-full resize-y rounded-md border bg-zinc-950/60 p-3 font-mono text-xs leading-relaxed text-zinc-200 shadow-sm outline-none transition-colors placeholder:text-zinc-600 focus-visible:ring-1 focus-visible:ring-primary/50",
              codeError ? "border-destructive/60" : "border-zinc-800 focus-visible:border-primary/40"
            )}
            placeholder="package swarmscan.policy&#10;&#10;default allow = true"
          />
          {codeError && <p className="text-[11px] text-destructive">{codeError}</p>}
          {/* live highlighted preview */}
          <div className="overflow-hidden rounded-md border border-zinc-800 bg-zinc-950/80">
            <div className="flex items-center justify-between border-b border-zinc-800/80 px-3 py-1.5">
              <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">
                live preview · rego
              </span>
              <span className="font-mono text-[10px] text-zinc-600">
                {code.split("\n").length} lines
              </span>
            </div>
            <div className="max-h-52 overflow-auto swarm-scroll">
              <SyntaxHighlighter
                language="go"
                style={oneDark}
                customStyle={{ margin: 0, background: "transparent", fontSize: "11px", padding: "0.75rem" }}
                codeTagProps={{ style: { fontFamily: "var(--font-mono), ui-monospace, monospace" } }}
              >
                {code || "# empty"}
              </SyntaxHighlighter>
            </div>
          </div>
          <p id="policy-code-hint" className="text-[11px] leading-relaxed text-zinc-500">
            {REGO_HINT}
          </p>
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={submitting} className="gap-2">
            {submitting && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />}
            {editing ? "Save policy" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
