"use client";

// ─── Targets view ────────────────────────────────────────────────────────────
// Registering a target is a PREREQUISITE for scanning. A target carries an
// engagement scope (Internal / External) and cannot be scanned until the
// operator attests authorization. This view is the only place targets are
// created, authorized and removed.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, Globe, Lock, Network, ShieldCheck, Trash2, TriangleAlert } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/swarm/format";
import { api, type CreateTargetPayload, type ScanScope, type TargetItem } from "@/lib/swarm/types";

const SCOPES: { value: ScanScope; title: string; desc: string; icon: typeof Globe }[] = [
  { value: "external", title: "External", desc: "Internet-facing hosts / domains (public addresses)", icon: Globe },
  { value: "internal", title: "Internal", desc: "Internal network ranges (RFC1918 / private hosts)", icon: Network },
];

export function TargetsView() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const { data: targets = [], isLoading } = useQuery({
    queryKey: ["targets"],
    queryFn: () => api<TargetItem[]>("/api/targets"),
  });

  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [scope, setScope] = useState<ScanScope>("external");
  const [environment, setEnvironment] = useState<"lab" | "external">("external");
  const [note, setNote] = useState("");
  const [attested, setAttested] = useState(false);

  const create = useMutation({
    mutationFn: (payload: CreateTargetPayload) =>
      api<TargetItem>("/api/targets", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["targets"] });
      setName("");
      setValue("");
      setNote("");
      setAttested(false);
      setEnvironment("external");
      toast({ title: "Target registered", description: "Add more or launch a scan from Scans." });
    },
    onError: (err) =>
      toast({ title: "Could not register target", description: err instanceof Error ? err.message : "error", variant: "destructive" }),
  });

  const authorize = useMutation({
    mutationFn: ({ id, authorized }: { id: string; authorized: boolean }) =>
      api<TargetItem>(`/api/targets/${id}`, { method: "PATCH", body: JSON.stringify({ authorized, attestedBy: "operator" }) }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["targets"] }),
    onError: (err) =>
      toast({ title: "Authorization change failed", description: err instanceof Error ? err.message : "error", variant: "destructive" }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api<{ ok: boolean }>(`/api/targets/${id}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["targets"] }),
  });

  const canSubmit = name.trim().length > 0 && value.trim().length > 0;

  const submit = () => {
    if (!canSubmit) return;
    create.mutate({ name: name.trim(), value: value.trim(), scope, environment, note: note.trim() || undefined, authorized: attested, attestedBy: attested ? "operator" : undefined });
  };

  const authorizedCount = targets.filter((t) => t.authorized).length;

  return (
    <div className="space-y-6">
      {/* Register form */}
      <Card className="p-5">
        <div className="mb-4 flex items-center gap-2">
          <Crosshair className="h-4 w-4 text-primary" aria-hidden />
          <h3 className="text-sm font-semibold">Register a target</h3>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="t-name" className="text-xs">Name <span className="text-red-400">*</span></Label>
            <Input id="t-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme production portal" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="t-value" className="text-xs">Host / IP / CIDR / URL <span className="text-red-400">*</span></Label>
            <Input id="t-value" value={value} onChange={(e) => setValue(e.target.value)} placeholder={scope === "internal" ? "10.0.4.0/24 or 192.168.1.20" : "portal.acme-corp.com"} className="font-mono text-[13px]" />
          </div>
        </div>

        <fieldset className="mt-4 space-y-2">
          <legend className="mb-1 text-xs font-medium">Engagement scope</legend>
          <div role="radiogroup" className="grid gap-2 sm:grid-cols-2">
            {SCOPES.map((s) => {
              const Icon = s.icon;
              const active = scope === s.value;
              return (
                <button
                  key={s.value}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  onClick={() => setScope(s.value)}
                  className={cn(
                    "flex items-start gap-2.5 rounded-lg border p-3 text-left transition-colors",
                    active ? "border-primary/50 bg-primary/10" : "border-border bg-muted/30 hover:border-zinc-600"
                  )}
                >
                  <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", active ? "text-primary" : "text-muted-foreground")} aria-hidden />
                  <span>
                    <span className="block text-[13px] font-semibold">{s.title}</span>
                    <span className="mt-0.5 block text-[11px] leading-4 text-muted-foreground">{s.desc}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </fieldset>

        <fieldset className="mt-4 space-y-2">
          <legend className="mb-1 text-xs font-medium">Environment</legend>
          <div role="radiogroup" className="grid gap-2 sm:grid-cols-2">
            {([
              { value: "external" as const, title: "External / real", desc: "Scanning & detection only (e.g. bug-bounty 'scan only'). No active exploitation." },
              { value: "lab" as const, title: "Lab / owned", desc: "Sandbox you control. Unlocks active proof-of-exploit (Owner + aggressive tier)." },
            ]).map((e) => {
              const active = environment === e.value;
              return (
                <button
                  key={e.value}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  onClick={() => setEnvironment(e.value)}
                  className={cn(
                    "flex items-start gap-2.5 rounded-lg border p-3 text-left transition-colors",
                    active ? "border-primary/50 bg-primary/10" : "border-border bg-muted/30 hover:border-zinc-600"
                  )}
                >
                  {e.value === "lab" ? (
                    <ShieldCheck className={cn("mt-0.5 h-4 w-4 shrink-0", active ? "text-primary" : "text-muted-foreground")} aria-hidden />
                  ) : (
                    <Globe className={cn("mt-0.5 h-4 w-4 shrink-0", active ? "text-primary" : "text-muted-foreground")} aria-hidden />
                  )}
                  <span>
                    <span className="block text-[13px] font-semibold">{e.title}</span>
                    <span className="mt-0.5 block text-[11px] leading-4 text-muted-foreground">{e.desc}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </fieldset>

        <div className="mt-4 space-y-1.5">
          <Label htmlFor="t-note" className="text-xs">Note <span className="font-normal text-muted-foreground">(optional)</span></Label>
          <Input id="t-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="engagement ref, owner, ticket…" />
        </div>

        <label className="mt-4 flex items-start gap-2.5 rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
          <Checkbox checked={attested} onCheckedChange={(v) => setAttested(v === true)} className="mt-0.5" aria-label="Attest authorization" />
          <span className="text-[12px] leading-5 text-amber-300/90">
            <span className="flex items-center gap-1.5 font-semibold text-amber-300"><ShieldCheck className="h-3.5 w-3.5" aria-hidden /> Authorization attestation</span>
            I confirm I am authorized to perform security testing against this target. Scans are blocked until this is attested.
          </span>
        </label>

        <div className="mt-4 flex items-center justify-between">
          <p className="text-[11px] text-muted-foreground">localhost / loopback is never accepted · scope is validated on save</p>
          <Button size="sm" disabled={!canSubmit || create.isPending} onClick={submit}>
            {create.isPending ? "Registering…" : attested ? "Register & authorize" : "Register (unauthorized)"}
          </Button>
        </div>
      </Card>

      {/* Target list */}
      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Registered targets</h3>
          <span className="font-mono text-[11px] text-muted-foreground">{authorizedCount}/{targets.length} authorized</span>
        </div>

        {isLoading ? (
          <p className="py-8 text-center text-xs text-muted-foreground">Loading…</p>
        ) : targets.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10 text-center">
            <Crosshair className="h-6 w-6 text-muted-foreground" aria-hidden />
            <p className="text-sm font-medium">No targets yet</p>
            <p className="max-w-sm text-xs text-muted-foreground">
              Register and authorize a target above — it is a prerequisite for launching any scan.
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {targets.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center gap-3 py-3">
                <span className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-md border", t.scope === "internal" ? "border-sky-500/30 bg-sky-500/10 text-sky-400" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400")}>
                  {t.scope === "internal" ? <Network className="h-3.5 w-3.5" aria-hidden /> : <Globe className="h-3.5 w-3.5" aria-hidden />}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[13px] font-medium">{t.name}</span>
                    <Badge variant="outline" className="h-4 px-1.5 text-[9px] uppercase tracking-wide">{t.scope}</Badge>
                    <Badge variant="outline" className={cn("h-4 px-1.5 text-[9px] uppercase tracking-wide", t.environment === "lab" ? "border-fuchsia-500/40 text-fuchsia-400" : "text-muted-foreground")}>{t.environment === "lab" ? "lab" : "ext"}</Badge>
                    <Badge variant="outline" className="h-4 px-1.5 text-[9px] uppercase tracking-wide text-muted-foreground">{t.kind}</Badge>
                  </div>
                  <span className="block truncate font-mono text-[11px] text-muted-foreground">{t.value}</span>
                </div>
                {t.authorized ? (
                  <Badge className="gap-1 bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/15"><ShieldCheck className="h-3 w-3" aria-hidden /> authorized</Badge>
                ) : (
                  <Badge variant="outline" className="gap-1 border-amber-500/40 text-amber-400"><TriangleAlert className="h-3 w-3" aria-hidden /> unauthorized</Badge>
                )}
                <div className="flex items-center gap-1.5">
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 text-[11px]"
                    disabled={authorize.isPending}
                    onClick={() => authorize.mutate({ id: t.id, authorized: !t.authorized })}
                  >
                    {t.authorized ? <><Lock className="mr-1 h-3 w-3" aria-hidden />Revoke</> : <><ShieldCheck className="mr-1 h-3 w-3" aria-hidden />Authorize</>}
                  </Button>
                  <Button size="icon" variant="ghost" className="h-7 w-7 text-muted-foreground hover:text-red-400" aria-label="Delete target" disabled={remove.isPending} onClick={() => remove.mutate(t.id)}>
                    <Trash2 className="h-3.5 w-3.5" aria-hidden />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
