"use client";

// ─── Remediation Report Component ─────────────────────────────────────────────
// Displays bulk virtual patches and source code fixes for all findings in a scan.

import { useState } from "react";
import {
  ShieldCheck,
  Download,
  Copy,
  Check,
  ExternalLink,
  Layers,
  Terminal,
  FileCode,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { BAND_STYLES, SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import type { Finding, ReportResponse } from "@/lib/swarm/types";
import { generateRemediationPackage, type RemediationPackage } from "@/lib/swarm/remediation";

export function RemediationReport({ report }: { report: ReportResponse }) {
  const { toast } = useToast();
  const setView = useSwarmUi((s) => s.setView);
  const openFinding = useSwarmUi((s) => s.openFinding);

  const findings: Finding[] = report.findings ?? [];
  const packages: RemediationPackage[] = (report.remediations as RemediationPackage[]) ?? findings.map(generateRemediationPackage);

  const [expandedId, setExpandedId] = useState<string | null>(packages[0]?.findingId ?? null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

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

  const downloadFile = (filename: string, content: string) => {
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
      title: "Export downloaded",
      description: `Saved ${filename}`,
    });
  };

  // Bulk generators
  const downloadAllCloudflare = () => {
    const rules = packages.map((pkg) => {
      const cf = pkg.wafRules.find((r) => r.provider === "cloudflare");
      return `# Rule for: ${pkg.title} [${pkg.endpoint}]\n${cf ? cf.code : ""}\n`;
    }).join("\n\n");
    downloadFile(`swarmscan-${report.scanId}-cloudflare-rules.txt`, rules);
  };

  const downloadAllModSecurity = () => {
    const rules = packages.map((pkg) => {
      const mod = pkg.wafRules.find((r) => r.provider === "modsecurity");
      return `# ${pkg.title}\n${mod ? mod.code : ""}`;
    }).join("\n\n");
    downloadFile(`swarmscan-${report.scanId}-modsecurity.conf`, rules);
  };

  const downloadAllAwsWaf = () => {
    const rules = packages.map((pkg, idx) => {
      const aws = pkg.wafRules.find((r) => r.provider === "awswaf");
      if (!aws) return null;
      try {
        const parsed = JSON.parse(aws.code);
        parsed.Priority = idx + 1;
        return parsed;
      } catch {
        return null;
      }
    }).filter(Boolean);
    downloadFile(`swarmscan-${report.scanId}-aws-waf-ruleset.json`, JSON.stringify(rules, null, 2));
  };

  const downloadAllPatches = () => {
    const patches = packages.map((pkg) => {
      const cd = pkg.codeRemediations[0];
      return cd ? `# Remediation for: ${pkg.title}\n${cd.gitPatch}` : "";
    }).join("\n\n");
    downloadFile(`swarmscan-${report.scanId}-remediations.patch`, patches);
  };

  if (findings.length === 0) {
    return (
      <Card className="border-dashed border-zinc-800 bg-zinc-950/40 p-8 text-center text-zinc-400">
        <ShieldCheck className="mx-auto h-8 w-8 text-emerald-400/80 mb-2" />
        <h3 className="text-sm font-medium text-zinc-200">No findings requiring remediation</h3>
        <p className="text-xs text-zinc-500 mt-1">This scan completed with zero detected vulnerabilities.</p>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* ── Summary & Bulk Exports ─────────────────────────────────────────── */}
      <Card className="border-emerald-500/30 bg-zinc-950/70">
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <CardTitle className="text-base text-zinc-100 flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-400" />
                Autonomous Remediation & Virtual Patching Suite
              </CardTitle>
              <CardDescription className="text-xs text-zinc-400 mt-1">
                Synthesized instant edge firewall defenses and source code fixes for all {packages.length} findings
              </CardDescription>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                className="h-8 gap-1.5 border-zinc-700 bg-zinc-900 text-xs hover:border-emerald-500/50 hover:text-emerald-400"
                onClick={downloadAllCloudflare}
              >
                <Download className="h-3.5 w-3.5" />
                Cloudflare Rules
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-8 gap-1.5 border-zinc-700 bg-zinc-900 text-xs hover:border-emerald-500/50 hover:text-emerald-400"
                onClick={downloadAllModSecurity}
              >
                <Download className="h-3.5 w-3.5" />
                ModSecurity Conf
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-8 gap-1.5 border-zinc-700 bg-zinc-900 text-xs hover:border-emerald-500/50 hover:text-emerald-400"
                onClick={downloadAllAwsWaf}
              >
                <Download className="h-3.5 w-3.5" />
                AWS WAF Rules
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-8 gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-xs text-emerald-400 hover:bg-emerald-500/20"
                onClick={downloadAllPatches}
              >
                <Download className="h-3.5 w-3.5" />
                All Git Patches (.patch)
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* ── Findings Remediation Accordion ──────────────────────────────────── */}
      <div className="space-y-3">
        {packages.map((pkg) => {
          const isExpanded = expandedId === pkg.findingId;
          const origFinding = findings.find((f) => f.id === pkg.findingId);
          const currentWaf = pkg.wafRules[0];
          const currentCode = pkg.codeRemediations[0];

          return (
            <Card
              key={pkg.findingId}
              className={`border-zinc-800 bg-zinc-950/60 transition-all ${
                isExpanded ? "ring-1 ring-emerald-500/30" : "hover:border-zinc-700"
              }`}
            >
              <div
                className="flex cursor-pointer flex-wrap items-center justify-between gap-3 p-4"
                onClick={() => setExpandedId(isExpanded ? null : pkg.findingId)}
              >
                <div className="flex items-center gap-3">
                  <Badge
                    variant="outline"
                    className={cn(
                      "px-2 py-0.5 text-[10px] uppercase tracking-wide",
                      SEVERITY_STYLES[pkg.severity].badge
                    )}
                  >
                    {SEVERITY_STYLES[pkg.severity].label}
                  </Badge>
                  {origFinding ? (
                    <Badge variant="outline" className={cn("px-2 py-0.5 text-[10px]", BAND_STYLES[origFinding.band].badge)}>
                      {BAND_STYLES[origFinding.band].label}
                    </Badge>
                  ) : null}
                  <div>
                    <h4 className="text-sm font-medium text-zinc-100">{pkg.title}</h4>
                    <p className="font-mono text-xs text-zinc-400 mt-0.5">{pkg.endpoint}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="border-zinc-800 bg-zinc-900 font-mono text-[11px] text-zinc-400">
                    <Zap className="mr-1 h-3 w-3 text-emerald-400" />
                    {pkg.wafRules.length} WAF Rules · {pkg.codeRemediations.length} Fixes
                  </Badge>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-8 gap-1 text-xs text-zinc-400 hover:text-white"
                    onClick={(e) => {
                      e.stopPropagation();
                      setView("findings");
                      openFinding(pkg.findingId);
                    }}
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    View Finding
                  </Button>
                </div>
              </div>

              {isExpanded ? (
                <CardContent className="border-t border-zinc-800/80 pt-4 space-y-4">
                  <p className="text-xs text-zinc-300">{pkg.summary}</p>

                  <div className="grid gap-4 lg:grid-cols-2">
                    {/* WAF Rule Preview */}
                    {currentWaf ? (
                      <div className="rounded-md border border-zinc-800 bg-zinc-900/60 p-3">
                        <div className="flex items-center justify-between border-b border-zinc-800 pb-2 mb-2">
                          <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-400">
                            <Terminal className="h-3.5 w-3.5" />
                            {currentWaf.providerLabel}
                          </span>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-6 gap-1 px-2 text-[11px] text-zinc-400 hover:text-white"
                            onClick={() =>
                              copyToClipboard(
                                `rep-waf-${pkg.findingId}`,
                                currentWaf.code,
                                currentWaf.providerLabel
                              )
                            }
                          >
                            {copiedKey === `rep-waf-${pkg.findingId}` ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            Copy Rule
                          </Button>
                        </div>
                        <pre className="max-h-[160px] overflow-x-auto font-mono text-[11px] text-emerald-400/90 swarm-scroll">
                          <code>{currentWaf.code}</code>
                        </pre>
                      </div>
                    ) : null}

                    {/* Code Remediation Preview */}
                    {currentCode ? (
                      <div className="rounded-md border border-zinc-800 bg-zinc-900/60 p-3">
                        <div className="flex items-center justify-between border-b border-zinc-800 pb-2 mb-2">
                          <span className="flex items-center gap-1.5 text-xs font-medium text-zinc-200">
                            <FileCode className="h-3.5 w-3.5 text-primary" />
                            {currentCode.label}
                          </span>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-6 gap-1 px-2 text-[11px] text-zinc-400 hover:text-white"
                            onClick={() =>
                              copyToClipboard(
                                `rep-patch-${pkg.findingId}`,
                                currentCode.gitPatch,
                                "Git Patch"
                              )
                            }
                          >
                            {copiedKey === `rep-patch-${pkg.findingId}` ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            Copy Patch
                          </Button>
                        </div>
                        <pre className="max-h-[160px] overflow-x-auto font-mono text-[11px] text-zinc-300 swarm-scroll">
                          <code>{currentCode.gitPatch}</code>
                        </pre>
                      </div>
                    ) : null}
                  </div>
                </CardContent>
              ) : null}
            </Card>
          );
        })}
      </div>
    </div>
  );
}
