"use client";

// ─── Remediation & Virtual Patching Card ──────────────────────────────────────
// Bridges the gap between vulnerability detection and defense:
//   • WAF Virtual Patches: Cloudflare, AWS WAF v2, ModSecurity / Coraza, NGINX
//   • Persistent Edge Deployment & Revocation backed by Prisma VirtualPatch
//   • Code-Level Remediation: Vulnerable vs Fixed snippets in TS, Python, Go
//   • Autonomous Remediation PR Staging & Unified Git .patch downloads

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  Code2,
  Copy,
  Check,
  Download,
  Terminal,
  FileCode,
  Sparkles,
  Zap,
  Layers,
  ArrowRight,
  GitPullRequest,
  Loader2,
  RotateCcw,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { api, type Finding } from "@/lib/swarm/types";
import {
  generateRemediationPackage,
  type FindingRemediationResponse,
} from "@/lib/swarm/remediation";
import { timeAgo } from "@/lib/swarm/format";

export function RemediationCard({ finding }: { finding: Finding }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const fallbackPkg = generateRemediationPackage(finding);

  const { data } = useQuery({
    queryKey: ["finding-remediation", finding.id],
    queryFn: () =>
      api<FindingRemediationResponse>(`/api/findings/${finding.id}/remediation`),
    initialData: {
      package: fallbackPkg,
      deployedPatches: [],
      remediationPrs: [],
    },
  });

  const pkg = data.package;
  const deployedPatches = data.deployedPatches ?? [];
  const remediationPrs = data.remediationPrs ?? [];

  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeWaf, setActiveWaf] = useState<string>(pkg.wafRules[0]?.provider || "cloudflare");
  const [activeLang, setActiveLang] = useState<string>(pkg.codeRemediations[0]?.language || "typescript");

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["finding-remediation", finding.id] });
    void queryClient.invalidateQueries({ queryKey: ["virtual-patches"] });
  };

  const deployMutation = useMutation({
    mutationFn: (provider: string) =>
      api(`/api/findings/${finding.id}/remediation/deploy`, {
        method: "POST",
        body: JSON.stringify({ provider }),
      }),
    onSuccess: (_res, provider) => {
      invalidate();
      const label = pkg.wafRules.find((r) => r.provider === provider)?.providerLabel ?? provider;
      toast({
        title: "Virtual Patch Deployed",
        description: `Edge rule persisted for ${label} on ${pkg.endpoint} and logged to SOC Event Bus.`,
      });
    },
    onError: (err) => {
      toast({
        title: "Virtual Patch deployment failed",
        description: err instanceof Error ? err.message : "Control plane unreachable",
        variant: "destructive",
      });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (provider: string) =>
      api(`/api/findings/${finding.id}/remediation/revoke`, {
        method: "POST",
        body: JSON.stringify({ provider }),
      }),
    onSuccess: (_res, provider) => {
      invalidate();
      const label = pkg.wafRules.find((r) => r.provider === provider)?.providerLabel ?? provider;
      toast({
        title: "Virtual Patch Revoked",
        description: `${label} edge rule deactivated for ${pkg.endpoint}.`,
      });
    },
    onError: (err) => {
      toast({
        title: "Revoke failed",
        description: err instanceof Error ? err.message : "Control plane unreachable",
        variant: "destructive",
      });
    },
  });

  const prMutation = useMutation({
    mutationFn: (language: string) =>
      api<{ integrationConnected?: boolean; vcsProvider?: string | null }>(
        `/api/findings/${finding.id}/remediation/pr`,
        {
          method: "POST",
          body: JSON.stringify({ language }),
        }
      ),
    onSuccess: (res, language) => {
      invalidate();
      toast({
        title: "Autonomous Remediation PR Staged",
        description: `Created branch and unified patch for ${language}${
          res?.integrationConnected && res.vcsProvider ? ` via ${res.vcsProvider}` : ""
        } with WORM evidence attestation.`,
      });
    },
    onError: (err) => {
      toast({
        title: "PR generation failed",
        description: err instanceof Error ? err.message : "Control plane unreachable",
        variant: "destructive",
      });
    },
  });

  const prStatusMutation = useMutation({
    mutationFn: ({ prId, status }: { prId: string; status: "opened" | "merged" | "closed" }) =>
      api(`/api/findings/${finding.id}/remediation/pr`, {
        method: "PATCH",
        body: JSON.stringify({ prId, status }),
      }),
    onSuccess: (_res, { status }) => {
      invalidate();
      toast({
        title: `PR marked ${status}`,
        description: `Remediation pull request status updated to ${status}.`,
      });
    },
    onError: (err) => {
      toast({
        title: "PR update failed",
        description: err instanceof Error ? err.message : "Control plane unreachable",
        variant: "destructive",
      });
    },
  });

  const copyToClipboard = (key: string, text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedKey(key);
    toast({
      title: "Copied to clipboard",
      description: `${label} copied to clipboard`,
    });
    setTimeout(() => {
      setCopiedKey((curr) => (curr === key ? null : curr));
    }, 2000);
  };

  const downloadText = (filename: string, content: string) => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({
      title: "File downloaded",
      description: `Saved ${filename}`,
    });
  };

  const currentWaf = pkg.wafRules.find((r) => r.provider === activeWaf) || pkg.wafRules[0];
  const currentCode = pkg.codeRemediations.find((c) => c.language === activeLang) || pkg.codeRemediations[0];

  const activeDeployedForCurrent = deployedPatches.find(
    (p) => p.provider === currentWaf?.provider && p.status === "deployed"
  );
  const totalActivePatches = deployedPatches.filter((p) => p.status === "deployed").length;

  return (
    <Card className="border-emerald-500/30 bg-zinc-950/80 shadow-md">
      <CardHeader className="border-b border-zinc-800/80 pb-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <div>
              <CardTitle className="text-base font-medium text-zinc-100 flex flex-wrap items-center gap-2">
                Autonomous Remediation & Virtual Patching
                <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 font-mono text-[10px] text-emerald-400">
                  <Sparkles className="mr-1 h-2.5 w-2.5" /> Instant Defense
                </Badge>
                {totalActivePatches > 0 ? (
                  <Badge className="border-emerald-500/50 bg-emerald-500/20 font-mono text-[10px] text-emerald-300">
                    <Zap className="mr-1 h-2.5 w-2.5 fill-emerald-400 text-emerald-400" />
                    {totalActivePatches} Active at Edge
                  </Badge>
                ) : null}
              </CardTitle>
              <CardDescription className="text-xs text-zinc-400">
                Generated edge firewall rules and source code patches for target endpoint{" "}
                <span className="font-mono text-zinc-300">{pkg.endpoint}</span>
              </CardDescription>
            </div>
          </div>

          {activeDeployedForCurrent ? (
            <div className="flex items-center gap-2">
              <Badge className="border-emerald-500/50 bg-emerald-500/20 text-emerald-300">
                <Zap className="mr-1 h-3 w-3 fill-emerald-400 text-emerald-400" />
                {currentWaf?.providerLabel} Active
              </Badge>
              <Button
                size="sm"
                variant="outline"
                className="h-8 gap-1.5 border-zinc-700 text-zinc-300 hover:border-red-500/50 hover:text-red-400"
                disabled={revokeMutation.isPending}
                onClick={() => currentWaf && revokeMutation.mutate(currentWaf.provider)}
              >
                {revokeMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <RotateCcw className="h-3.5 w-3.5" />
                )}
                Revoke
              </Button>
            </div>
          ) : (
            <Button
              size="sm"
              variant="outline"
              className="h-8 gap-1.5 border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-300"
              disabled={deployMutation.isPending || !currentWaf}
              onClick={() => currentWaf && deployMutation.mutate(currentWaf.provider)}
            >
              {deployMutation.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Zap className="h-3.5 w-3.5" />
              )}
              Deploy to {currentWaf?.providerLabel || "WAF"}
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="pt-4">
        <Tabs defaultValue="waf" className="w-full">
          <TabsList className="mb-4 grid w-full max-w-md grid-cols-2 bg-zinc-900">
            <TabsTrigger value="waf" className="gap-1.5 text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-emerald-400">
              <Layers className="h-3.5 w-3.5" /> WAF Virtual Patches ({pkg.wafRules.length})
            </TabsTrigger>
            <TabsTrigger value="code" className="gap-1.5 text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-emerald-400">
              <Code2 className="h-3.5 w-3.5" /> Code Remediation ({pkg.codeRemediations.length})
            </TabsTrigger>
          </TabsList>

          {/* ── TAB 1: WAF VIRTUAL PATCHES ───────────────────────────────────── */}
          <TabsContent value="waf" className="space-y-4 outline-none">
            {/* Provider selector pills */}
            <div className="flex flex-wrap items-center gap-2">
              {pkg.wafRules.map((rule) => {
                const isSelected = activeWaf === rule.provider;
                const isDeployed = deployedPatches.some(
                  (p) => p.provider === rule.provider && p.status === "deployed"
                );
                return (
                  <button
                    key={rule.provider}
                    type="button"
                    onClick={() => setActiveWaf(rule.provider)}
                    className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-all ${
                      isSelected
                        ? "bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/50"
                        : "bg-zinc-900/90 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                    }`}
                  >
                    <Terminal className="h-3 w-3" />
                    {rule.providerLabel}
                    {isDeployed ? (
                      <span className="ml-1 h-1.5 w-1.5 rounded-full bg-emerald-400" title="Deployed at Edge" />
                    ) : null}
                  </button>
                );
              })}
            </div>

            {currentWaf ? (
              <div className="space-y-3">
                <div className="rounded-md border border-zinc-800/80 bg-zinc-900/40 p-3 text-xs text-zinc-300">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                    <p className="font-medium text-zinc-200">{currentWaf.title}</p>
                    {activeDeployedForCurrent ? (
                      <span className="font-mono text-[10px] text-emerald-400">
                        deployed {timeAgo(activeDeployedForCurrent.deployedAt)} · id {activeDeployedForCurrent.ruleId}
                      </span>
                    ) : null}
                  </div>
                  <p className="text-zinc-400">{currentWaf.explanation}</p>
                </div>

                {/* Code block with toolbar */}
                <div className="relative rounded-md border border-zinc-800 bg-zinc-950">
                  <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-1.5 text-[11px] text-zinc-400">
                    <span className="font-mono text-zinc-400">{currentWaf.filename}</span>
                    <div className="flex items-center gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 gap-1 px-2 text-xs text-zinc-300 hover:text-white"
                        onClick={() =>
                          copyToClipboard(`waf-${currentWaf.provider}`, currentWaf.code, currentWaf.providerLabel)
                        }
                      >
                        {copiedKey === `waf-${currentWaf.provider}` ? (
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
                        onClick={() => downloadText(currentWaf.filename, currentWaf.code)}
                      >
                        <Download className="h-3.5 w-3.5" />
                        Download
                      </Button>
                    </div>
                  </div>
                  <pre className="max-h-[320px] overflow-x-auto p-3 font-mono text-xs leading-relaxed text-emerald-400/90 swarm-scroll">
                    <code>{currentWaf.code}</code>
                  </pre>
                </div>
              </div>
            ) : null}
          </TabsContent>

          {/* ── TAB 2: CODE-LEVEL REMEDIATION ────────────────────────────────── */}
          <TabsContent value="code" className="space-y-4 outline-none">
            <div className="flex flex-wrap items-center justify-between gap-2">
              {/* Language selector pills */}
              <div className="flex flex-wrap items-center gap-2">
                {pkg.codeRemediations.map((rem) => {
                  const isSelected = activeLang === rem.language;
                  return (
                    <button
                      key={rem.language}
                      type="button"
                      onClick={() => setActiveLang(rem.language)}
                      className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-all ${
                        isSelected
                          ? "bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/50"
                          : "bg-zinc-900/90 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                      }`}
                    >
                      <FileCode className="h-3 w-3" />
                      {rem.label}
                    </button>
                  );
                })}
              </div>

              {currentCode ? (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-8 gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-xs text-emerald-300 hover:bg-emerald-500/20"
                  disabled={prMutation.isPending}
                  onClick={() => prMutation.mutate(currentCode.language)}
                >
                  {prMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <GitPullRequest className="h-3.5 w-3.5" />
                  )}
                  Stage Remediation PR
                </Button>
              ) : null}
            </div>

            {currentCode ? (
              <div className="space-y-4">
                <div className="rounded-md border border-zinc-800/80 bg-zinc-900/40 p-3 text-xs text-zinc-300">
                  <p className="font-medium text-zinc-200 mb-1">Root Cause Fix</p>
                  <p className="text-zinc-400">{currentCode.explanation}</p>
                </div>

                <div className="grid gap-4 lg:grid-cols-2">
                  {/* Vulnerable snippet */}
                  <div className="rounded-md border border-red-500/30 bg-zinc-950">
                    <div className="flex items-center justify-between border-b border-red-500/20 bg-red-950/20 px-3 py-1.5 text-[11px] text-red-300">
                      <span className="font-mono">Vulnerable Implementation</span>
                      <Badge variant="outline" className="border-red-500/40 bg-red-500/10 text-[10px] text-red-400">
                        Before
                      </Badge>
                    </div>
                    <pre className="max-h-[260px] overflow-x-auto p-3 font-mono text-[11px] leading-relaxed text-red-300/90 swarm-scroll">
                      <code>{currentCode.vulnerableSnippet}</code>
                    </pre>
                  </div>

                  {/* Fixed snippet */}
                  <div className="rounded-md border border-emerald-500/30 bg-zinc-950">
                    <div className="flex items-center justify-between border-b border-emerald-500/20 bg-emerald-950/20 px-3 py-1.5 text-[11px] text-emerald-300">
                      <span className="font-mono">Secure Fix</span>
                      <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-[10px] text-emerald-400">
                        After
                      </Badge>
                    </div>
                    <pre className="max-h-[260px] overflow-x-auto p-3 font-mono text-[11px] leading-relaxed text-emerald-300/90 swarm-scroll">
                      <code>{currentCode.fixedSnippet}</code>
                    </pre>
                  </div>
                </div>

                {/* Git Unified Patch block */}
                <div className="rounded-md border border-zinc-800 bg-zinc-950">
                  <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-1.5 text-[11px] text-zinc-400">
                    <span className="flex items-center gap-1.5 font-mono text-zinc-400">
                      <ArrowRight className="h-3 w-3 text-emerald-400" />
                      Git Unified Diff Patch ({currentCode.filename})
                    </span>
                    <div className="flex items-center gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 gap-1 px-2 text-xs text-zinc-300 hover:text-white"
                        onClick={() =>
                          copyToClipboard(`patch-${currentCode.language}`, currentCode.gitPatch, "Git Patch")
                        }
                      >
                        {copiedKey === `patch-${currentCode.language}` ? (
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                        Copy Patch
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 gap-1 px-2 text-xs text-zinc-300 hover:text-white"
                        onClick={() => downloadText(`remediation-${currentCode.language}.patch`, currentCode.gitPatch)}
                      >
                        <Download className="h-3.5 w-3.5" />
                        Download .patch
                      </Button>
                    </div>
                  </div>
                  <pre className="max-h-[180px] overflow-x-auto p-3 font-mono text-[11px] leading-relaxed text-zinc-300 swarm-scroll">
                    <code>{currentCode.gitPatch}</code>
                  </pre>
                </div>

                {/* Staged Autonomous PRs */}
                {remediationPrs.length > 0 ? (
                  <div className="space-y-2 rounded-md border border-emerald-500/20 bg-zinc-900/40 p-3">
                    <p className="flex items-center gap-1.5 text-xs font-medium text-emerald-300">
                      <GitPullRequest className="h-3.5 w-3.5" />
                      Staged Remediation Pull Requests ({remediationPrs.length})
                    </p>
                    <div className="space-y-2">
                      {remediationPrs.map((pr) => (
                        <div
                          key={pr.id}
                          className="flex flex-wrap items-center justify-between gap-2 rounded border border-zinc-800 bg-zinc-950/80 px-3 py-2 text-xs"
                        >
                          <div className="min-w-0">
                            <p className="truncate font-medium text-zinc-200">{pr.prTitle}</p>
                            <p className="font-mono text-[11px] text-zinc-400">
                              branch: {pr.branchName} · {pr.language} · {timeAgo(pr.createdAt)}
                            </p>
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge
                              variant="outline"
                              className={
                                pr.status === "merged"
                                  ? "border-teal-500/40 bg-teal-500/10 text-[10px] text-teal-300"
                                  : pr.status === "closed"
                                    ? "border-zinc-700 bg-zinc-900 text-[10px] text-zinc-400"
                                    : "border-emerald-500/40 bg-emerald-500/10 text-[10px] text-emerald-400"
                              }
                            >
                              {pr.status}
                            </Badge>
                            {pr.status === "opened" ? (
                              <>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-[11px] text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-300"
                                  disabled={prStatusMutation.isPending}
                                  onClick={() => prStatusMutation.mutate({ prId: pr.id, status: "merged" })}
                                >
                                  Mark Merged
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2 text-[11px] text-zinc-400 hover:text-red-400"
                                  disabled={prStatusMutation.isPending}
                                  onClick={() => prStatusMutation.mutate({ prId: pr.id, status: "closed" })}
                                >
                                  Close
                                </Button>
                              </>
                            ) : null}
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-7 gap-1 px-2 text-[11px] text-zinc-300 hover:text-white"
                              onClick={() => copyToClipboard(`pr-${pr.id}`, pr.prBody, "PR Markdown")}
                            >
                              {copiedKey === `pr-${pr.id}` ? (
                                <Check className="h-3 w-3 text-emerald-400" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                              Copy PR Body
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            ) : null}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
