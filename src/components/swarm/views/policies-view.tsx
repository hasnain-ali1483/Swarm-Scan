"use client";

// ─── Policies view — OPA/Rego policy engine + scope firewall + payload gates ──

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Plus, RotateCcw, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { useToast } from "@/hooks/use-toast";
import { api, type PoliciesResponse, type PolicyItem, type ScopeRuleItem } from "@/lib/swarm/types";
import { PolicyCard } from "@/components/swarm/policies/policy-card";
import { PolicyDialog, type PolicyDraft } from "@/components/swarm/policies/policy-dialog";
import { ScopeRuleCard } from "@/components/swarm/policies/scope-rule-card";
import { ScopeRuleDialog, type ScopeDraft } from "@/components/swarm/policies/scope-rule-dialog";
import { PayloadRegistry } from "@/components/swarm/policies/payload-registry";
import { TimeWindowBar } from "@/components/swarm/policies/time-window-bar";
import { VirtualPatchesPanel } from "@/components/swarm/policies/virtual-patches-panel";

type DeleteTarget =
  | { type: "policy"; item: PolicyItem }
  | { type: "scope"; item: ScopeRuleItem };

export function PoliciesView() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [policyDialogOpen, setPolicyDialogOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<PolicyItem | null>(null);
  const [policySession, setPolicySession] = useState(0);
  const [scopeDialogOpen, setScopeDialogOpen] = useState(false);
  const [editingScope, setEditingScope] = useState<ScopeRuleItem | null>(null);
  const [scopeSession, setScopeSession] = useState(0);
  const [deleting, setDeleting] = useState<DeleteTarget | null>(null);

  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    isRefetching,
  } = useQuery({
    queryKey: ["policies"],
    queryFn: () => api<PoliciesResponse>("/api/policies"),
  });

  const policies = data?.policies ?? [];
  const scopeRules = data?.scopeRules ?? [];
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["policies"] });

  const errToast = (action: string, e: unknown) =>
    toast({
      title: `${action} failed`,
      description: e instanceof Error ? e.message : "Control plane unreachable",
      variant: "destructive",
    });

  // ── Policy mutations ───────────────────────────────────────────────────────
  const createPolicy = useMutation({
    mutationFn: (draft: PolicyDraft) =>
      api("/api/policies", { method: "POST", body: JSON.stringify(draft) }),
    onSuccess: (_res, draft) => {
      toast({
        title: "Policy created",
        description: `"${draft.name}" is now evaluated per request by the control plane.`,
      });
      void invalidate();
      setPolicyDialogOpen(false);
    },
    onError: (e) => errToast("Create policy", e),
  });

  const updatePolicy = useMutation({
    mutationFn: ({
      id,
      patch,
      action,
    }: {
      id: string;
      patch: Partial<PolicyDraft>;
      action: "toggle" | "edit";
    }) => api(`/api/policies/${id}`, { method: "PUT", body: JSON.stringify(patch) }),
    onSuccess: (_res, { action, patch }) => {
      if (action === "toggle") {
        toast({
          title: `Policy ${patch.enabled ? "enabled" : "disabled"}`,
          description: patch.enabled
            ? "Violations now abort agent states and write to the audit ledger."
            : "Policy kept in version control but skips evaluation.",
        });
      } else {
        toast({
          title: "Policy updated",
          description: "Change staged — the OPA sidecar hot-reloads the bundle.",
        });
      }
      void invalidate();
      setPolicyDialogOpen(false);
    },
    onError: (e) => errToast("Update policy", e),
  });

  const deletePolicy = useMutation({
    mutationFn: (id: string) => api(`/api/policies/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast({ title: "Policy deleted", description: "Removed from the evaluation bundle." });
      void invalidate();
      setDeleting(null);
    },
    onError: (e) => errToast("Delete policy", e),
  });

  // ── Scope rule mutations ───────────────────────────────────────────────────
  const createScope = useMutation({
    mutationFn: (draft: ScopeDraft) =>
      api("/api/scope", { method: "POST", body: JSON.stringify(draft) }),
    onSuccess: (_res, draft) => {
      toast({
        title: "Scope rule created",
        description: `"${draft.name}" compiled into eBPF/LSM filters across worker microVMs.`,
      });
      void invalidate();
      setScopeDialogOpen(false);
    },
    onError: (e) => errToast("Create scope rule", e),
  });

  const updateScope = useMutation({
    mutationFn: ({
      id,
      patch,
      action,
    }: {
      id: string;
      patch: Partial<ScopeDraft>;
      action: "toggle" | "edit";
    }) => api(`/api/scope/${id}`, { method: "PUT", body: JSON.stringify(patch) }),
    onSuccess: (_res, { action, patch }) => {
      if (action === "toggle") {
        toast({
          title: `Scope rule ${patch.enforced ? "enforced" : "relaxed to advisory"}`,
          description: patch.enforced
            ? "Packets to out-of-scope CIDRs are now dropped at the socket layer."
            : "App-layer checks only — packets are no longer dropped in-kernel.",
        });
      } else {
        toast({
          title: "Scope rule updated",
          description: "Worker microVMs re-compiled their socket filters.",
        });
      }
      void invalidate();
      setScopeDialogOpen(false);
    },
    onError: (e) => errToast("Update scope rule", e),
  });

  const deleteScope = useMutation({
    mutationFn: (id: string) => api(`/api/scope/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      toast({ title: "Scope rule deleted", description: "Filters removed from worker microVMs." });
      void invalidate();
      setDeleting(null);
    },
    onError: (e) => errToast("Delete scope rule", e),
  });

  const busy =
    createPolicy.isPending ||
    updatePolicy.isPending ||
    deletePolicy.isPending ||
    createScope.isPending ||
    updateScope.isPending ||
    deleteScope.isPending;

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px]">
      {/* ── Section A — Policy engine ─────────────────────────────────────── */}
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Policy Engine</h2>
          <span className="flex items-center gap-1.5 rounded-sm border border-zinc-700 bg-zinc-900/60 px-2 py-0.5 font-mono text-[10px] text-zinc-400">
            Policy-as-code · OPA/Rego
          </span>
        </div>
        <Button
          size="sm"
          className="gap-2"
          onClick={() => {
            setEditingPolicy(null);
            setPolicySession((s) => s + 1);
            setPolicyDialogOpen(true);
          }}
          aria-label="Create new policy"
        >
          <Plus className="h-4 w-4" aria-hidden />
          New policy
        </Button>
      </header>

      <div className="mt-4">
        {isError ? (
          <Alert variant="destructive">
            <AlertTitle>Could not load policies</AlertTitle>
            <AlertDescription className="flex items-center gap-2">
              <span className="min-w-0 truncate">
                {error instanceof Error ? error.message : "Control plane unreachable"}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void refetch()}
                className="gap-1.5"
                disabled={isRefetching}
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        ) : isLoading ? (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {Array.from({ length: 4 }, (_, i) => (
              <Skeleton key={i} className="h-48 rounded-lg" />
            ))}
          </div>
        ) : policies.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-800 p-10 text-center">
            <ShieldCheck className="mx-auto h-6 w-6 text-zinc-600" aria-hidden />
            <p className="mt-2 text-sm text-zinc-300">No policies yet</p>
            <p className="mt-1 text-xs text-zinc-500">
              Without policies every request is evaluated against the built-in safe defaults.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {policies.map((policy, i) => (
              <motion.div
                key={policy.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(i * 0.05, 0.4), duration: 0.25 }}
              >
                <PolicyCard
                  policy={policy}
                  index={i}
                  busy={busy}
                  onToggle={(p, enabled) =>
                    updatePolicy.mutate({ id: p.id, patch: { enabled }, action: "toggle" })
                  }
                  onEdit={(p) => {
                    setEditingPolicy(p);
                    setPolicySession((s) => s + 1);
                    setPolicyDialogOpen(true);
                  }}
                  onDelete={(p) => setDeleting({ type: "policy", item: p })}
                />
              </motion.div>
            ))}
          </div>
        )}
      </div>

      {/* ── Section B — Scope firewall ────────────────────────────────────── */}
      <header className="mt-10 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Scope Firewall</h2>
          <span className="flex items-center gap-1.5 rounded-sm border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-400">
            kernel-enforced · eBPF/LSM in worker microVMs
          </span>
        </div>
        <Button
          size="sm"
          className="gap-2"
          onClick={() => {
            setEditingScope(null);
            setScopeSession((s) => s + 1);
            setScopeDialogOpen(true);
          }}
          aria-label="Create new scope rule"
        >
          <Plus className="h-4 w-4" aria-hidden />
          New rule
        </Button>
      </header>
      <p className="mt-1 text-xs text-zinc-500">
        Packets to out-of-scope CIDRs are dropped at the socket layer — app-layer checks are
        advisory only.
      </p>

      <div className="mt-4">
        {isError ? (
          <Alert variant="destructive">
            <AlertTitle>Could not load scope rules</AlertTitle>
            <AlertDescription>Retry from the policy engine error above.</AlertDescription>
          </Alert>
        ) : isLoading ? (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {Array.from({ length: 2 }, (_, i) => (
              <Skeleton key={i} className="h-40 rounded-lg" />
            ))}
          </div>
        ) : scopeRules.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-800 p-10 text-center">
            <p className="text-sm text-zinc-300">No scope rules defined</p>
            <p className="mt-1 text-xs text-zinc-500">
              Agents may probe anything routable — add an allowlist to constrain the blast radius.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {scopeRules.map((rule, i) => (
              <motion.div
                key={rule.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(i * 0.05, 0.4), duration: 0.25 }}
              >
                <ScopeRuleCard
                  rule={rule}
                  busy={busy}
                  onToggle={(r, enforced) =>
                    updateScope.mutate({ id: r.id, patch: { enforced }, action: "toggle" })
                  }
                  onEdit={(r) => {
                    setEditingScope(r);
                    setScopeSession((s) => s + 1);
                    setScopeDialogOpen(true);
                  }}
                  onDelete={(r) => setDeleting({ type: "scope", item: r })}
                />
              </motion.div>
            ))}
          </div>
        )}
      </div>

      {/* ── Sections C + D — payload registry & time window ───────────────── */}
      <div className="mt-10 grid gap-4 lg:grid-cols-2">
        <PayloadRegistry />
        <TimeWindowBar />
      </div>

      {/* ── Section E — active WAF virtual patches ─────────────────────────── */}
      <div className="mt-10">
        <VirtualPatchesPanel />
      </div>

      {/* ── Dialogs ───────────────────────────────────────────────────────── */}
      <PolicyDialog
        key={`policy-dialog-${policySession}`}
        open={policyDialogOpen}
        onOpenChange={setPolicyDialogOpen}
        editing={editingPolicy}
        submitting={createPolicy.isPending || updatePolicy.isPending}
        onSubmit={(draft) => {
          if (editingPolicy) {
            updatePolicy.mutate({ id: editingPolicy.id, patch: draft, action: "edit" });
          } else {
            createPolicy.mutate(draft);
          }
        }}
      />

      <ScopeRuleDialog
        key={`scope-dialog-${scopeSession}`}
        open={scopeDialogOpen}
        onOpenChange={setScopeDialogOpen}
        editing={editingScope}
        submitting={createScope.isPending || updateScope.isPending}
        onSubmit={(draft) => {
          if (editingScope) {
            updateScope.mutate({ id: editingScope.id, patch: draft, action: "edit" });
          } else {
            createScope.mutate(draft);
          }
        }}
      />

      <AlertDialog
        open={!!deleting}
        onOpenChange={(open) => !open && setDeleting(null)}
      >
        <AlertDialogContent className="bg-zinc-950/95">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {deleting?.type === "policy" ? "Delete policy" : "Delete scope rule"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {deleting && (
                <>
                  <code className="font-mono text-xs text-zinc-300">{deleting.item.name}</code>{" "}
                  {deleting.type === "policy"
                    ? "will be removed from the evaluation bundle. In-flight requests finish under the rules already loaded."
                    : "will be removed from worker microVMs. Out-of-scope CIDRs will no longer be dropped in-kernel."}
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={busy}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={(e) => {
                e.preventDefault();
                if (!deleting) return;
                if (deleting.type === "policy") deletePolicy.mutate(deleting.item.id);
                else deleteScope.mutate(deleting.item.id);
              }}
            >
              {busy ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
