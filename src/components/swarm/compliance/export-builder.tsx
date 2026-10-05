"use client";

// ─── Export builder — option checkboxes + estimate + RBAC-gated seal ─────────

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Download, Loader2, Lock, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { roleCan } from "@/lib/swarm/access-roles";
import { cn } from "@/lib/swarm/format";
import type { AccessRole, ComplianceExportOptions, CompliancePack } from "@/lib/swarm/types";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { useExportPack } from "./use-compliance";

const OPTIONS: {
  key: keyof ComplianceExportOptions;
  label: string;
  hint: string;
}[] = [
  {
    key: "includeRawEvidence",
    label: "Include raw evidence payloads (WORM content)",
    hint: "Full ledger row contents inside the bundle — hash-chained, still tamper-evident.",
  },
  {
    key: "includeSarif",
    label: "Attach SARIF 2.1 summary",
    hint: "Rule index over all findings — machine-readable companion for CI tooling.",
  },
  {
    key: "anonymize",
    label: "Anonymize — strip content, keep hashes",
    hint: "Raw payloads reduced to hashes + kinds; the chain stays verifiable.",
  },
];

/** Byte-per-artifact estimate weights (matches the server bundle shape). */
const EST_BYTES = { control: 420, evidence: 260, sarif: 180, raw: 620, rawAnon: 120 };

export function ExportBuilder({ pack }: { pack: CompliancePack }) {
  const actingRole = useSwarmUi((s) => s.actingRole) as AccessRole;
  const canExport = roleCan(actingRole, "reports:export");
  const exportPack = useExportPack();

  const [options, setOptions] = useState<ComplianceExportOptions>({
    includeRawEvidence: false,
    includeSarif: false,
    anonymize: false,
  });

  const estimate = useMemo(() => {
    const evidenceEntries = pack.summary.evidenceEntries;
    const sections = 3 + (options.includeSarif ? 1 : 0) + (options.includeRawEvidence ? 1 : 0);
    const entries =
      pack.controls.length +
      evidenceEntries +
      1 +
      (options.includeSarif ? pack.summary.findingsCovered : 0) +
      (options.includeRawEvidence ? evidenceEntries : 0);
    const bytes =
      EST_BYTES.control * pack.controls.length +
      EST_BYTES.evidence * evidenceEntries +
      300 +
      (options.includeSarif ? EST_BYTES.sarif * pack.summary.findingsCovered : 0) +
      (options.includeRawEvidence
        ? evidenceEntries * (options.anonymize ? EST_BYTES.rawAnon : EST_BYTES.raw)
        : 0);
    return { sections, entries, kb: Math.max(1, Math.round(bytes / 1024)) };
  }, [options, pack]);

  const toggle = (key: keyof ComplianceExportOptions) => (checked: boolean) =>
    setOptions((prev) => ({ ...prev, [key]: checked }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Card className="border-border/80 bg-card/40">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center justify-between gap-2 text-sm">
            <span className="flex items-center gap-2">
              <Download className="h-4 w-4 text-primary" aria-hidden />
              Export builder
            </span>
            <span className="font-mono text-[10px] font-normal uppercase tracking-wider text-muted-foreground">
              auditor bundle
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pb-4">
          <div className="space-y-3">
            {OPTIONS.map((opt) => (
              <div key={opt.key} className="flex items-start gap-2.5">
                <Checkbox
                  id={`export-${opt.key}`}
                  checked={options[opt.key]}
                  onCheckedChange={(v) => toggle(opt.key)(v === true)}
                  className="mt-0.5"
                  aria-label={opt.label}
                />
                <div className="min-w-0">
                  <Label
                    htmlFor={`export-${opt.key}`}
                    className="cursor-pointer text-xs leading-relaxed font-normal text-zinc-300"
                  >
                    {opt.label}
                  </Label>
                  <p className="mt-0.5 text-[10px] leading-relaxed text-zinc-600">{opt.hint}</p>
                </div>
              </div>
            ))}
          </div>

          <p className="rounded-md border border-zinc-800 bg-zinc-950/50 px-2.5 py-2 font-mono text-[10px] text-zinc-500">
            ~{estimate.entries} entries · {estimate.sections} manifest sections · est.{" "}
            {estimate.kb} KB · sealed receipt + audit-trail row
          </p>

          <div className="flex items-center justify-between gap-2">
            <span className="flex min-w-0 items-center gap-1.5 font-mono text-[10px] text-zinc-600">
              <ShieldCheck className="h-3 w-3 shrink-0" aria-hidden />
              <span className="truncate">
                reports:export · {canExport ? "granted" : "denied"} for {actingRole}
              </span>
            </span>

            <Tooltip>
              <TooltipTrigger asChild>
                <span className="inline-flex">
                  <Button
                    size="sm"
                    disabled={!canExport || exportPack.isPending}
                    onClick={() => exportPack.mutate(options)}
                    className={cn("gap-2", !canExport && "cursor-not-allowed")}
                    aria-label={
                      canExport
                        ? "Export SOC 2 evidence pack"
                        : `reports:export denied for ${actingRole}`
                    }
                  >
                    {exportPack.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                    ) : !canExport ? (
                      <Lock className="h-3.5 w-3.5" aria-hidden />
                    ) : (
                      <Download className="h-3.5 w-3.5" aria-hidden />
                    )}
                    Export pack
                  </Button>
                </span>
              </TooltipTrigger>
              {!canExport ? (
                <TooltipContent>reports:export denied for {actingRole}</TooltipContent>
              ) : null}
            </Tooltip>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
