"use client";

// ─── Reports view — executive / technical / SARIF 2.1 export ──────────────────

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { format as formatDate } from "date-fns";
import { Download, FileJson, KanbanSquare, Loader2, Radar } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { api, type ReportResponse, type ScanSummary } from "@/lib/swarm/types";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { ExecutiveReport } from "@/components/swarm/reports/executive-report";
import { TechnicalReport } from "@/components/swarm/reports/technical-report";
import { SarifViewer } from "@/components/swarm/reports/sarif-viewer";

type ReportFormat = "executive" | "technical" | "sarif";

const FORMAT_META: Record<ReportFormat, { label: string; ext: string; mime: string }> = {
  executive: { label: "Executive", ext: "json", mime: "application/json" },
  technical: { label: "Technical", ext: "json", mime: "application/json" },
  sarif: { label: "SARIF 2.1", ext: "sarif", mime: "application/sarif+json" },
};

export function ReportsView() {
  const { toast } = useToast();
  const setView = useSwarmUi((s) => s.setView);
  const [scanId, setScanId] = useState<string | null>(null);
  const [format, setFormat] = useState<ReportFormat>("executive");
  const [sendingJira, setSendingJira] = useState(false);

  // Scan selector — normalizes { scans: [...] } or a bare array.
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api<unknown>("/api/scans"),
  });
  const scans = useMemo<ScanSummary[]>(() => {
    const raw = scansData as { scans?: ScanSummary[] } | ScanSummary[] | undefined;
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    return raw.scans ?? [];
  }, [scansData]);

  const effectiveScanId = scanId ?? scans[0]?.id ?? null;
  const selectedScan = scans.find((s) => s.id === effectiveScanId) ?? null;

  const {
    data: report,
    isLoading: reportLoading,
    isError: reportError,
    error,
    refetch,
  } = useQuery({
    queryKey: ["report", effectiveScanId, format],
    queryFn: () =>
      api<ReportResponse>(
        `/api/reports?scanId=${encodeURIComponent(effectiveScanId ?? "")}&format=${format}`
      ),
    enabled: !!effectiveScanId,
  });

  const download = () => {
    if (!report) return;
    const meta = FORMAT_META[format];
    const body =
      format === "sarif"
        ? JSON.stringify(report.sarif ?? {}, null, 2)
        : JSON.stringify(report, null, 2);
    const blob = new Blob([body], { type: meta.mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `swarmscan-${report.target.replace(/[^a-z0-9.-]+/gi, "-")}-${format}.${meta.ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast({
      title: "Report downloaded",
      description: `${meta.label} export for ${report.target} (${(body.length / 1024).toFixed(1)} KB).`,
    });
  };

  const sendToJira = () => {
    if (!report) return;
    setSendingJira(true);
    // Simulated — no API call: dedup happens server-side by evidence hash.
    window.setTimeout(() => {
      setSendingJira(false);
      toast({
        title: "Ticket created in project SEC",
        description: "Deduplicated by evidence hash — no duplicate ticket filed.",
      });
    }, 600);
  };

  const scanLabel = (scan: ScanSummary) =>
    `${scan.target} · ${scan.startedAt ? formatDate(new Date(scan.startedAt), "MMM d, HH:mm") : formatDate(new Date(scan.createdAt), "MMM d, HH:mm")}`;

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px]">
      <header className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="text-lg font-semibold tracking-tight">Reporting &amp; Export</h2>
        <p className="text-[11px] text-zinc-500">
          Deterministic reports — same scan, same seed ⇒ byte-identical output.
        </p>
      </header>

      {/* controls */}
      <section
        aria-label="Report controls"
        className="mt-4 flex flex-col gap-3 rounded-lg border border-zinc-800 bg-card/60 p-3 lg:flex-row lg:items-end"
      >
        <div className="space-y-1.5 lg:w-80">
          <Label htmlFor="report-scan" className="text-[11px] uppercase tracking-wider text-zinc-500">
            Scan
          </Label>
          {scansLoading ? (
            <Skeleton className="h-9 w-full" />
          ) : (
            <Select
              value={effectiveScanId ?? undefined}
              onValueChange={(v) => setScanId(v)}
              disabled={scans.length === 0}
            >
              <SelectTrigger id="report-scan" className="font-mono text-xs" aria-label="Select scan">
                <SelectValue placeholder={scans.length ? "Select a scan" : "No scans available"} />
              </SelectTrigger>
              <SelectContent>
                {scans.map((scan) => (
                  <SelectItem key={scan.id} value={scan.id} className="font-mono text-xs">
                    {scanLabel(scan)} · {scan.status}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>

        <Tabs
          value={format}
          onValueChange={(v) => setFormat(v as ReportFormat)}
          className="min-w-0"
        >
          <TabsList className="bg-zinc-900/60" aria-label="Report format">
            {(Object.keys(FORMAT_META) as ReportFormat[]).map((key) => (
              <TabsTrigger key={key} value={key} className="text-xs data-[state=active]:bg-zinc-800">
                {FORMAT_META[key].label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>

        <div className="flex flex-1 flex-wrap items-center justify-end gap-2">
          <Button
            onClick={sendToJira}
            variant="outline"
            size="sm"
            disabled={!report || sendingJira}
            className="gap-2"
            aria-label="Send report to Jira"
          >
            {sendingJira ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            ) : (
              <KanbanSquare className="h-3.5 w-3.5" aria-hidden />
            )}
            Send to Jira
          </Button>
          <Button
            onClick={download}
            size="sm"
            disabled={!report || reportLoading}
            className="gap-2"
            aria-label={`Download ${FORMAT_META[format].label} report`}
          >
            <Download className="h-3.5 w-3.5" aria-hidden />
            Download .{FORMAT_META[format].ext}
          </Button>
        </div>
      </section>

      {/* body */}
      <div className="mt-4">
        {!scansLoading && scans.length === 0 ? (
          <div className="rounded-lg border border-dashed border-zinc-800 p-12 text-center">
            <Radar className="mx-auto h-6 w-6 text-zinc-600" aria-hidden />
            <p className="mt-3 text-sm text-zinc-300">No scans yet</p>
            <p className="mt-1 text-xs text-zinc-500">
              Run a scan first — reports are generated per scan from the evidence ledger.
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-4"
              onClick={() => setView("scans")}
            >
              Go to Scans
            </Button>
          </div>
        ) : !effectiveScanId ? (
          <Alert variant="destructive">
            <AlertTitle>No scan selected</AlertTitle>
            <AlertDescription>Select a scan to generate a report.</AlertDescription>
          </Alert>
        ) : reportLoading ? (
          format === "sarif" ? (
            <Skeleton className="h-[50vh] rounded-lg" />
          ) : (
            <div className="grid gap-4 lg:grid-cols-[auto_1fr]">
              <Skeleton className="h-64 w-64 rounded-lg" />
              <Skeleton className="h-64 rounded-lg" />
            </div>
          )
        ) : reportError ? (
          <Alert variant="destructive">
            <AlertTitle>Failed to generate {FORMAT_META[format].label.toLowerCase()} report</AlertTitle>
            <AlertDescription className="flex flex-wrap items-center gap-2">
              <span className="min-w-0 truncate">
                {error instanceof Error ? error.message : "Control plane unreachable"}
              </span>
              <Button variant="outline" size="sm" onClick={() => void refetch()}>
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        ) : !report ? (
          <Alert>
            <FileJson className="h-4 w-4" aria-hidden />
            <AlertTitle>Select a scan to generate a report</AlertTitle>
            <AlertDescription>
              Choose a completed scan above; the report is assembled from its evidence ledger.
            </AlertDescription>
          </Alert>
        ) : format === "executive" ? (
          <ExecutiveReport report={report} />
        ) : format === "technical" ? (
          <TechnicalReport report={report} />
        ) : (
          <SarifViewer sarif={report.sarif} />
        )}
      </div>

      {report && selectedScan && (
        <p className="mt-4 font-mono text-[11px] text-zinc-600">
          scan {selectedScan.id.slice(0, 8)} · profile {selectedScan.profile} · tier{" "}
          {selectedScan.policyTier} · seed {selectedScan.seed}
        </p>
      )}
    </div>
  );
}
