"use client";

// ─── API keys — scoped machine credentials, secret shown once (Task 9-b) ────

import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Check, Copy, KeyRound, Plus, ShieldOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { AccessMutationResponse, ApiKeyItem } from "@/lib/swarm/types";
import { API_KEY_SCOPES } from "@/lib/swarm/access-roles";
import { cn, timeAgo } from "@/lib/swarm/format";
import { useAccessMutation } from "./use-access";

function KeyRow({ k, revoking, onRevoke }: { k: ApiKeyItem; revoking: boolean; onRevoke: (id: string) => void }) {
  const revoked = k.revokedAt != null;
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border px-4 py-3 transition-colors",
        revoked
          ? "border-red-500/20 bg-red-500/[0.03] opacity-70"
          : "border-border bg-card/60 hover:border-primary/30 hover:bg-card"
      )}
    >
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <span
          className={cn(
            "flex h-8 w-8 shrink-0 items-center justify-center rounded-md border",
            revoked
              ? "border-red-500/25 bg-red-500/10 text-red-400"
              : "border-primary/25 bg-primary/10 text-primary"
          )}
        >
          <KeyRound className="h-4 w-4" aria-hidden />
        </span>
        <div className="min-w-0">
          <div className="truncate text-sm font-medium">{k.label}</div>
          <div className="truncate font-mono text-[10px] text-muted-foreground" title={`prefix ${k.prefix}`}>
            {k.prefix} · created {timeAgo(k.createdAt)} by {k.createdBy}
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {k.scopes.map((s) => (
          <code
            key={s}
            className="rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-[9px] text-zinc-300"
          >
            {s}
          </code>
        ))}
      </div>
      <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
        {revoked ? (
          <span className="inline-flex items-center gap-1 text-red-400">
            <ShieldOff className="h-3 w-3" aria-hidden />
            revoked {timeAgo(k.revokedAt!)}
          </span>
        ) : k.lastUsedAt ? (
          <span title={new Date(k.lastUsedAt).toLocaleString()}>used {timeAgo(k.lastUsedAt)}</span>
        ) : (
          <span>never used</span>
        )}
        {!revoked ? (
          <Button
            variant="ghost"
            size="sm"
            disabled={revoking}
            onClick={() => onRevoke(k.id)}
            className="h-7 gap-1.5 text-[11px] text-red-400 hover:bg-red-500/10 hover:text-red-400"
            aria-label={`Revoke key ${k.label}`}
          >
            <ShieldOff className="h-3.5 w-3.5" aria-hidden />
            Revoke
          </Button>
        ) : null}
      </div>
    </div>
  );
}

export function ApiKeysSection({ keys }: { keys: ApiKeyItem[] }) {
  const mutation = useAccessMutation();
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [scopes, setScopes] = useState<string[]>(["findings:read"]);
  const [created, setCreated] = useState<AccessMutationResponse["key"] | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) {
      // reset dialog state when closed
      setLabel("");
      setScopes(["findings:read"]);
      setCreated(null);
      setCopied(false);
      setError(null);
    }
  };

  const toggleScope = (scope: string, checked: boolean) => {
    setScopes((prev) => (checked ? [...new Set([...prev, scope])] : prev.filter((s) => s !== scope)));
  };

  const create = async () => {
    setError(null);
    if (label.trim().length < 3) {
      setError("Label must be at least 3 characters");
      return;
    }
    if (scopes.length === 0) {
      setError("Select at least one scope");
      return;
    }
    try {
      const res = await mutation.mutateAsync({ action: "key.create", label: label.trim(), scopes });
      if (res.ok && res.key) {
        setCreated(res.key);
      } else {
        setError(res.message);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create key");
    }
  };

  const copySecret = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable — user can select manually */
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] text-muted-foreground">
          Scoped machine credentials for CI pipelines and SIEM pulls — secrets are shown once at
          creation and never stored.
        </p>
        <Button
          size="sm"
          onClick={() => setOpen(true)}
          className="h-8 gap-1.5 text-xs"
          aria-label="Create API key"
        >
          <Plus className="h-3.5 w-3.5" aria-hidden />
          New key
        </Button>
      </div>

      <div className="space-y-2">
        <AnimatePresence initial={false}>
          {keys.map((k) => (
            <motion.div
              key={k.id}
              layout
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98 }}
              transition={{ duration: 0.18 }}
            >
              <KeyRow k={k} revoking={mutation.isPending} onRevoke={(id) => mutation.mutate({ action: "key.revoke", id })} />
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="sm:max-w-md">
          {!created ? (
            <>
              <DialogHeader>
                <DialogTitle className="gap-2 flex items-center">
                  <KeyRound className="h-4 w-4 text-primary" aria-hidden />
                  Create API key
                </DialogTitle>
                <DialogDescription>
                  Scoped credential — grant the minimum the pipeline needs. The secret is displayed
                  exactly once.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-1">
                <div className="space-y-1.5">
                  <Label htmlFor="key-label" className="text-xs">
                    Label
                  </Label>
                  <Input
                    id="key-label"
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    placeholder="e.g. Nightly SOC export"
                    className="text-sm"
                    maxLength={60}
                  />
                </div>
                <fieldset className="space-y-2">
                  <legend className="text-xs font-medium">Scopes</legend>
                  <div className="grid gap-2">
                    {API_KEY_SCOPES.map((s) => (
                      <label
                        key={s.key}
                        className="flex cursor-pointer items-start gap-3 rounded-md border border-border bg-card/40 px-3 py-2 transition-colors hover:border-primary/30 hover:bg-accent/40"
                      >
                        <Checkbox
                          checked={scopes.includes(s.key)}
                          onCheckedChange={(checked) => toggleScope(s.key, checked === true)}
                          className="mt-0.5"
                          aria-label={`Scope ${s.key}`}
                        />
                        <span className="min-w-0">
                          <code className="font-mono text-xs text-primary">{s.key}</code>
                          <span className="block text-[11px] text-muted-foreground">{s.hint}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </fieldset>
                {error ? (
                  <p role="alert" className="text-xs text-destructive">
                    {error}
                  </p>
                ) : null}
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => handleOpenChange(false)} className="text-xs">
                  Cancel
                </Button>
                <Button onClick={() => void create()} disabled={mutation.isPending} className="gap-1.5 text-xs">
                  {mutation.isPending ? "Creating…" : "Create key"}
                </Button>
              </DialogFooter>
            </>
          ) : (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-primary" aria-hidden />
                  Secret — copy it now
                </DialogTitle>
                <DialogDescription>
                  This is the only time the full key is shown. Store it in a secret manager
                  (Vault/AWS SM) — the ledger keeps only the prefix.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-3 py-1">
                <button
                  type="button"
                  onClick={() => void copySecret()}
                  className="group relative flex w-full items-center gap-3 rounded-md border border-primary/30 bg-primary/5 px-3 py-3 text-left transition-colors hover:border-primary/50"
                  aria-label="Copy secret to clipboard"
                >
                  <code className="min-w-0 flex-1 break-all font-mono text-xs text-primary">{created.secret}</code>
                  {copied ? (
                    <Check className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
                  ) : (
                    <Copy className="h-4 w-4 shrink-0 text-muted-foreground group-hover:text-primary" aria-hidden />
                  )}
                </button>
                <p className="font-mono text-[10px] text-muted-foreground">
                  prefix {created.secret.slice(0, 12)}… · label “{created.label}”
                </p>
              </div>
              <DialogFooter>
                <Button
                  onClick={() => handleOpenChange(false)}
                  className="text-xs"
                  variant="outline"
                >
                  I saved the secret
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
