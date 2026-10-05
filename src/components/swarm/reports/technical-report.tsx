"use client";

// ─── Technical report — full findings table wired to the Findings view ────────

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { FileCode2, Inbox } from "lucide-react";
import { BAND_STYLES, SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import type { Finding, ReportResponse } from "@/lib/swarm/types";
import { AGENT_BY_KEY } from "@/lib/swarm/agents-catalog";
import { useSwarmUi } from "@/lib/swarm/ui-store";

function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity as Finding["severity"]];
  return (
    <Badge
      variant="outline"
      className={cn("px-1.5 text-[10px] capitalize", style?.badge ?? "")}
    >
      {style?.label ?? severity}
    </Badge>
  );
}

function BandBadge({ band, confidence }: { band: string; confidence: number }) {
  const style = BAND_STYLES[band as Finding["band"]];
  return (
    <span className="flex items-center gap-1.5">
      <Badge variant="outline" className={cn("px-1.5 text-[10px]", style?.badge ?? "")}>
        {style?.label ?? band}
      </Badge>
      <span className="font-mono text-[11px] text-zinc-400">
        {Math.round(confidence)}%
      </span>
    </span>
  );
}

export function TechnicalReport({ report }: { report: ReportResponse }) {
  const setView = useSwarmUi((s) => s.setView);
  const openFinding = useSwarmUi((s) => s.openFinding);
  const findings = report.findings ?? [];

  return (
    <div className="space-y-3">
      <div className="max-h-[70vh] overflow-auto swarm-scroll rounded-lg border border-zinc-800 bg-card/60">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-zinc-950/95 backdrop-blur">
            <TableRow className="border-zinc-800 hover:bg-transparent">
              <TableHead className="text-[11px] uppercase tracking-wider text-zinc-500">
                Severity
              </TableHead>
              <TableHead className="text-[11px] uppercase tracking-wider text-zinc-500">
                Finding
              </TableHead>
              <TableHead className="hidden text-[11px] uppercase tracking-wider text-zinc-500 md:table-cell">
                Agent
              </TableHead>
              <TableHead className="hidden text-[11px] uppercase tracking-wider text-zinc-500 lg:table-cell">
                Target / endpoint
              </TableHead>
              <TableHead className="text-[11px] uppercase tracking-wider text-zinc-500">
                Confidence
              </TableHead>
              <TableHead className="hidden text-[11px] uppercase tracking-wider text-zinc-500 sm:table-cell">
                Evidence
              </TableHead>
              <TableHead className="text-[11px] uppercase tracking-wider text-zinc-500">
                CVE
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {findings.length === 0 ? (
              <TableRow className="border-zinc-800/70">
                <TableCell colSpan={7} className="h-32 text-center">
                  <Inbox className="mx-auto h-5 w-5 text-zinc-600" aria-hidden />
                  <p className="mt-2 text-sm text-zinc-300">No findings recorded</p>
                  <p className="mt-1 text-xs text-zinc-500">
                    This scan completed without confirmed or suspected issues.
                  </p>
                </TableCell>
              </TableRow>
            ) : (
              findings.map((f) => (
                <TableRow
                  key={f.id}
                  onClick={() => {
                    setView("findings");
                    openFinding(f.id);
                  }}
                  className="cursor-pointer border-zinc-800/70 transition-colors hover:bg-primary/5"
                  aria-label={`Open finding ${f.title}`}
                >
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="max-w-[260px]">
                    <div className="truncate text-xs font-medium text-zinc-100">{f.title}</div>
                    <div className="truncate text-[10px] text-zinc-500">{f.category}</div>
                  </TableCell>
                  <TableCell className="hidden font-mono text-[11px] text-zinc-400 md:table-cell">
                    {AGENT_BY_KEY[f.agentKey]?.name ?? f.agentKey}
                  </TableCell>
                  <TableCell className="hidden max-w-[220px] lg:table-cell">
                    <div className="truncate font-mono text-[11px] text-zinc-400">
                      {f.endpoint ? `${f.target}${f.endpoint}` : f.target}
                    </div>
                  </TableCell>
                  <TableCell>
                    <BandBadge band={f.band} confidence={f.confidence} />
                  </TableCell>
                  <TableCell className="hidden sm:table-cell">
                    <span className="inline-flex items-center gap-1 rounded-sm border border-zinc-700 bg-zinc-900/60 px-1.5 py-px font-mono text-[10px] text-zinc-300">
                      <FileCode2 className="h-3 w-3 text-zinc-500" aria-hidden />
                      {f.evidence?.length ?? 0}
                    </span>
                  </TableCell>
                  <TableCell>
                    {f.cve ? (
                      <span className="rounded-sm border border-red-500/30 bg-red-500/10 px-1.5 py-px font-mono text-[10px] text-red-400">
                        {f.cve}
                      </span>
                    ) : (
                      <span className="font-mono text-[10px] text-zinc-600">—</span>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <p className="text-[11px] leading-relaxed text-zinc-500">
        Every finding ships a working PoC plan + reproduction script generated from the evidence
        ledger. Click a row to open the full Bayesian evidence trail.
      </p>
    </div>
  );
}
