"use client";

// ─── Remediation & Virtual Patching Card ──────────────────────────────────────
// Bridges the gap between vulnerability detection and defense:
//   • WAF Virtual Patches: Cloudflare, AWS WAF v2, ModSecurity / Coraza, NGINX
//   • Code-Level Remediation: Vulnerable vs Fixed snippets in TS, Python, Go
//   • Unified Git .patch generation and downloads

import { useState } from "react";
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
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import type { Finding } from "@/lib/swarm/types";
import { generateRemediationPackage, type RemediationPackage } from "@/lib/swarm/remediation";

export function RemediationCard({ finding }: { finding: Finding }) {
  const { toast } = useToast();
  const pkg: RemediationPackage = generateRemediationPackage(finding);

  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeWaf, setActiveWaf] = useState<string>(pkg.wafRules[0]?.provider || "cloudflare");
  const [activeLang, setActiveLang] = useState<string>(pkg.codeRemediations[0]?.language || "typescript");
  const [simulatedDeploy, setSimulatedDeploy] = useState<boolean>(false);

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

  const handleSimulateDeploy = (providerName: string) => {
    setSimulatedDeploy(true);
    toast({
      title: "Virtual Patch Deployed",
      description: `Simulated edge deployment to ${providerName}. Zero-day attack surface mitigated.`,
    });
  };

  const currentWaf = pkg.wafRules.find((r) => r.provider === activeWaf) || pkg.wafRules[0];
  const currentCode = pkg.codeRemediations.find((c) => c.language === activeLang) || pkg.codeRemediations[0];

  return (
    <Card className="border-emerald-500/30 bg-zinc-950/80 shadow-md">
      <CardHeader className="border-b border-zinc-800/80 pb-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <div>
              <CardTitle className="text-base font-medium text-zinc-100 flex items-center gap-2">
                Autonomous Remediation & Virtual Patching
                <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 font-mono text-[10px] text-emerald-400">
                  <Sparkles className="mr-1 h-2.5 w-2.5" /> Instant Defense
                </Badge>
              </CardTitle>
              <CardDescription className="text-xs text-zinc-400">
                Generated edge firewall rules and source code patches for target endpoint{" "}
                <span className="font-mono text-zinc-300">{pkg.endpoint}</span>
              </CardDescription>
            </div>
          </div>

          {simulatedDeploy ? (
            <Badge className="border-emerald-500/50 bg-emerald-500/20 text-emerald-300">
              <Zap className="mr-1 h-3 w-3 fill-emerald-400 text-emerald-400" /> Virtual Patch Active at Edge
            </Badge>
          ) : (
            <Button
              size="sm"
              variant="outline"
              className="h-8 gap-1.5 border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-300"
              onClick={() => handleSimulateDeploy(currentWaf?.providerLabel || "WAF")}
            >
              <Zap className="h-3.5 w-3.5" /> Deploy Virtual Patch
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
                  </button>
                );
              })}
            </div>

            {currentWaf ? (
              <div className="space-y-3">
                <div className="rounded-md border border-zinc-800/80 bg-zinc-900/40 p-3 text-xs text-zinc-300">
                  <p className="font-medium text-zinc-200 mb-1">{currentWaf.title}</p>
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
              </div>
            ) : null}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
