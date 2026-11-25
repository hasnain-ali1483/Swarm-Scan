"use client";

// ─── Active Virtual Patches Panel (Policies View) ────────────────────────────
// Displays all persisted WAF virtual patches deployed from findings, with
// provider filtering, rule copy, finding jump, and one-click revoke/re-deploy.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Copy,
  ExternalLink,
  Loader2,
  RotateCcw,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { api } from "@/lib/swarm/types";
import { timeAgo } from "@/lib/swarm/format";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import type { DeployedPatchItem } from "@/lib/swarm/remediation";

interface VirtualPatchesResponse {
  patches: DeployedPatchItem[];
  summary: {
    total: number;
    deployed: number;
    revoked: number;
  };
}

const PROVIDER_LABELS: Record<string, string> = {
  cloudflare: "Cloudflare WAF",
  awswaf: "AWS WAF v2",
  modsecurity: "ModSecurity / Coraza",
  nginx: "NGINX",
};

export function VirtualPatchesPanel() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const setView = useSwarmUi((s) => s.setView);
  const openFinding = useSwarmUi((s) => s.openFinding);

  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["virtual-patches"],
    queryFn: () => api<VirtualPatchesResponse>("/api/virtual-patches"),
  });

  const patches = data?.patches ?? [];
  const filtered =
    providerFilter === "all"
      ? patches
      : patches.filter((p) => p.provider === providerFilter);

  const toggleMutation = useMutation({
    mutationFn: ({ findingId, provider, nextAction }: { findingId: string; provider: string; nextAction: "deploy" | "revoke" }) =>
      api(`/api/findings/${findingId}/remediation/${nextAction}`, {
        method: "POST",
        body: JSON.stringify({ provider }),
      }),
    onSuccess: (_res, { provider, nextAction }) => {
      void queryClient.invalidateQueries({ queryKey: ["virtual-patches"] });
      toast({
        title: nextAction === "deploy" ? "Virtual Patch Deployed" : "Virtual Patch Revoked",
        description: `${PROVIDER_LABELS[provider] ?? provider} rule ${nextAction === "deploy" ? "activated" : "deactivated"}.`,
      });
    },
    onError: (err) => {
      toast({
        title: "Patch update failed",
        description: err instanceof Error ? err.message : "Control plane unreachable",
        variant: "destructive",
      });
    },
  });

  const handleCopy = (id: string, content: string, provider: string) => {
    void navigator.clipboard.writeText(content);
    setCopiedId(id);
    toast({
      title: "Rule copied",
      description: `${PROVIDER_LABELS[provider] ?? provider} rule copied to clipboard.`,
    });
    setTimeout(() => setCopiedId((c) => (c === id ? null : c)), 2000);
  };

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-base font-semibold tracking-tight">
            <ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden />
            Active WAF Virtual Patches
          </h3>
          <p className="text-xs text-zinc-400">
            Edge firewall rules synthesized from verified findings and deployed across Cloudflare, AWS WAF, ModSecurity, and NGINX.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 font-mono text-[11px] text-emerald-400">
            <Zap className="mr-1 h-3 w-3" />
            {data?.summary.deployed ?? 0} active
          </Badge>
          <Badge variant="outline" className="border-zinc-700 bg-zinc-900 font-mono text-[11px] text-zinc-400">
            {data?.summary.revoked ?? 0} revoked
          </Badge>
        </div>
      </div>

      {/* Provider filter chips */}
      <div className="flex flex-wrap items-center gap-1.5">
        {["all", "cloudflare", "awswaf", "modsecurity", "nginx"].map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => setProviderFilter(p)}
            className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
              providerFilter === p
                ? "bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/40"
                : "bg-zinc-900 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
            }`}
          >
            {p === "all" ? "All Providers" : PROVIDER_LABELS[p]}
          </button>
        ))}
      </div>

      {isLoading ? (
        <Card className="border-zinc-800 bg-zinc-950/60 p-6 text-center text-xs text-zinc-400">
          Loading virtual patches…
        </Card>
      ) : filtered.length === 0 ? (
        <Card className="border-dashed border-zinc-800 bg-zinc-950/40 p-6 text-center">
          <ShieldCheck className="mx-auto mb-2 h-6 w-6 text-zinc-600" aria-hidden />
          <p className="text-sm text-zinc-300">No virtual patches deployed yet</p>
          <p className="mt-1 text-xs text-zinc-500">
            Open any finding and click <span className="font-mono text-zinc-300">Deploy to WAF</span> to shield the endpoint at the edge.
          </p>
        </Card>
      ) : (
        <div className="grid gap-3">
          {filtered.map((patch) => {
            const isActive = patch.status === "deployed";
            return (
              <Card
                key={patch.id}
                className={`border-zinc-800 bg-zinc-950/70 ${
                  isActive ? "border-l-2 border-l-emerald-500" : "opacity-75"
                }`}
              >
                <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 pb-2">
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge
                        variant="outline"
                        className={
                          isActive
                            ? "border-emerald-500/40 bg-emerald-500/10 text-[10px] text-emerald-400"
                            : "border-zinc-700 bg-zinc-900 text-[10px] text-zinc-400"
                        }
                      >
                        {isActive ? "ACTIVE AT EDGE" : "REVOKED"}
                      </Badge>
                      <Badge variant="outline" className="border-zinc-700 bg-zinc-900 font-mono text-[10px] text-zinc-300">
                        {PROVIDER_LABELS[patch.provider] ?? patch.provider}
                      </Badge>
                      <span className="font-mono text-[11px] text-zinc-500">{patch.ruleId}</span>
                    </div>
                    <CardTitle className="text-sm text-zinc-100">
                      {patch.findingTitle ?? patch.endpoint}
                    </CardTitle>
                    <CardDescription className="font-mono text-[11px] text-zinc-400">
                      {patch.findingTarget ? `${patch.findingTarget} · ` : ""}
                      endpoint {patch.endpoint} · deployed {timeAgo(patch.deployedAt)}
                    </CardDescription>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 gap-1 px-2 text-xs text-zinc-300 hover:text-white"
                      onClick={() => handleCopy(patch.id, patch.ruleContent, patch.provider)}
                    >
                      {copiedId === patch.id ? (
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                      Copy
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 gap-1 px-2 text-xs text-zinc-300 hover:text-white"
                      onClick={() => {
                        setView("findings");
                        openFinding(patch.findingId);
                      }}
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                      Finding
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className={`h-7 gap-1 px-2.5 text-xs ${
                        isActive
                          ? "border-zinc-700 text-zinc-300 hover:border-red-500/40 hover:text-red-400"
                          : "border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10"
                      }`}
                      disabled={toggleMutation.isPending}
                      onClick={() =>
                        toggleMutation.mutate({
                          findingId: patch.findingId,
                          provider: patch.provider,
                          nextAction: isActive ? "revoke" : "deploy",
                        })
                      }
                    >
                      {toggleMutation.isPending ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : isActive ? (
                        <RotateCcw className="h-3 w-3" />
                      ) : (
                        <Zap className="h-3 w-3" />
                      )}
                      {isActive ? "Revoke" : "Re-deploy"}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <pre className="max-h-24 overflow-x-auto rounded border border-zinc-800/80 bg-zinc-900/50 p-2 font-mono text-[11px] text-emerald-400/85 swarm-scroll">
                    <code>{patch.ruleContent}</code>
                  </pre>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </section>
  );
}
