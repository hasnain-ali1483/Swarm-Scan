"use client";

// ─── Findings list: filters, paginated result table (lg) / cards (mobile) ────
// Subscribes to engine `finding:new` events → toast + list invalidation.

import { useEffect, useMemo, useState } from "react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ChevronLeft, ChevronRight, Search, ShieldCheck, Siren, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useEngineSocket } from "@/components/swarm/providers";
import {
  api,
  SEVERITY_ORDER,
  type ConfidenceBand,
  type Finding,
  type FindingsListResponse,
  type Severity,
} from "@/lib/swarm/types";
import {
  BAND_STYLES,
  SEVERITY_STYLES,
  cn,
  formatNumber,
  timeAgo,
} from "@/lib/swarm/format";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { EmptyState, ErrorState, ListSkeleton } from "./states";

const PAGE_SIZE = 20;

/** The 15 spec'd agent keys (static filter list). */
const AGENT_KEYS = [
  "recon",
  "fingerprint",
  "crawler",
  "ssrf",
  "injection",
  "xss",
  "fileops",
  "deser",
  "auth",
  "api",
  "crypto",
  "cloud",
  "correlator",
  "revisit",
  "evasion",
] as const;

type BandFilter = "all" | ConfidenceBand;

function confidenceBarColor(confidence: number): string {
  if (confidence >= 85) return "bg-emerald-500";
  if (confidence >= 60) return "bg-amber-500";
  return "bg-zinc-500";
}

// ─── Row (grid on lg, card below) ────────────────────────────────────────────

function FindingRow({
  finding,
  shielded,
  onOpen,
}: {
  finding: Finding;
  shielded: boolean;
  onOpen: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      role="button"
      tabIndex={0}
      aria-label={`Open finding: ${SEVERITY_STYLES[finding.severity].label} — ${finding.title}`}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
      className="group flex cursor-pointer flex-col gap-2.5 rounded-lg border border-border bg-card/40 px-4 py-3 outline-none transition-colors hover:border-zinc-600 hover:bg-card/70 focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/40 lg:grid lg:grid-cols-[92px_minmax(0,1fr)_104px_140px_96px_64px] lg:items-center lg:gap-3 lg:py-2.5"
    >
      {/* severity */}
      <div className="flex items-center gap-2">
        <span className={cn("h-2 w-2 shrink-0 rounded-full", SEVERITY_STYLES[finding.severity].dot)} aria-hidden />
        <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px] uppercase tracking-wide", SEVERITY_STYLES[finding.severity].badge)}>
          {SEVERITY_STYLES[finding.severity].label}
        </Badge>
      </div>

      {/* title + target */}
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <p className="line-clamp-2 text-sm font-medium leading-snug text-zinc-100 group-hover:text-white">
            {finding.title}
          </p>
          {shielded ? (
            <Badge
              variant="outline"
              className="border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0 text-[10px] text-emerald-400"
              title="Active WAF Virtual Patch deployed at edge"
            >
              <ShieldCheck className="mr-1 h-2.5 w-2.5" aria-hidden />
              Shielded
            </Badge>
          ) : null}
        </div>
        <p className="mt-0.5 truncate font-mono text-[11px] text-zinc-500">
          {finding.endpoint ? `${finding.target}${finding.endpoint}` : finding.target}
        </p>
      </div>

      {/* agent */}
      <div>
        <Badge variant="outline" className="max-w-full truncate border-zinc-700/70 bg-zinc-900/50 px-1.5 py-0 font-mono text-[10px] text-zinc-400">
          {finding.agentKey}
        </Badge>
      </div>

      {/* confidence */}
      <div className="flex items-center gap-2" title={`Confidence ${finding.confidence}/99 (${finding.band})`}>
        <div className="h-1.5 w-16 shrink-0 overflow-hidden rounded-full bg-zinc-800 lg:w-20" aria-hidden>
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${Math.min(100, Math.max(0, finding.confidence))}%` }}
            transition={{ duration: 0.5, ease: "easeOut" }}
            className={cn("h-full rounded-full", confidenceBarColor(finding.confidence))}
          />
        </div>
        <span className="font-mono text-xs tabular-nums text-zinc-300">{finding.confidence.toFixed(1)}</span>
      </div>

      {/* band */}
      <div>
        <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", BAND_STYLES[finding.band].badge)}>
          {BAND_STYLES[finding.band].label}
        </Badge>
      </div>

      {/* time */}
      <span className="text-[11px] text-zinc-500 lg:text-right" title={new Date(finding.createdAt).toISOString()}>
        {timeAgo(finding.createdAt)}
      </span>
    </motion.div>
  );
}

// ─── List ────────────────────────────────────────────────────────────────────

export function FindingsList() {
  const openFinding = useSwarmUi((s) => s.openFinding);
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { on } = useEngineSocket();

  const [severities, setSeverities] = useState<Severity[]>([]);
  const [band, setBand] = useState<BandFilter>("all");
  const [shieldFilter, setShieldFilter] = useState<"all" | "shielded" | "unshielded">("all");
  const [agentKey, setAgentKey] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");

  // Debounced search (300ms)
  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedQ(search.trim()), 300);
    return () => window.clearTimeout(t);
  }, [search]);

  // Pagination resets whenever any filter changes — derived during render
  // (filter signature + page live in one state object, no effect needed).
  const filtersKey = `${severities.join(",")}|${band}|${agentKey}|${debouncedQ}`;
  const [pageState, setPageState] = useState<{ key: string; page: number }>({ key: "", page: 1 });
  const page = pageState.key === filtersKey ? pageState.page : 1;
  const setPage = (next: number | ((prev: number) => number)) =>
    setPageState({
      key: filtersKey,
      page: typeof next === "function" ? next(page) : next,
    });

  // Live finding:new events → toast + invalidate list
  useEffect(() => {
    return on("finding:new", (payload) => {
      const f = payload.finding;
      if (!f) return;
      toast({
        title: `New finding: ${SEVERITY_STYLES[f.severity]?.label ?? f.severity} · ${f.title}`,
        description: `confidence ${f.confidence}/99 · ${f.band} · agent ${f.agentKey}`,
      });
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
    });
  }, [on, queryClient, toast]);

  const queryString = useMemo(() => {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("pageSize", String(PAGE_SIZE));
    if (severities.length > 0) params.set("severity", severities.join(","));
    if (band !== "all") params.set("band", band);
    if (agentKey !== "all") params.set("agentKey", agentKey);
    if (debouncedQ) params.set("q", debouncedQ);
    return params.toString();
  }, [page, severities, band, agentKey, debouncedQ]);

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["findings", { severities, band, agentKey, q: debouncedQ, page }],
    queryFn: () => api<FindingsListResponse>(`/api/findings?${queryString}`),
    placeholderData: keepPreviousData,
  });

  const { data: patchesData } = useQuery({
    queryKey: ["virtual-patches", "deployed"],
    queryFn: () =>
      api<{ patches: { findingId: string }[] }>("/api/virtual-patches?status=deployed"),
  });

  const shieldedIds = useMemo(
    () => new Set((patchesData?.patches ?? []).map((p) => p.findingId)),
    [patchesData]
  );

  const findings = data?.findings ?? [];
  const visibleFindings = useMemo(() => {
    if (shieldFilter === "shielded") return findings.filter((f) => shieldedIds.has(f.id));
    if (shieldFilter === "unshielded") return findings.filter((f) => !shieldedIds.has(f.id));
    return findings;
  }, [findings, shieldFilter, shieldedIds]);
  const total = data?.total ?? 0;
  const lastPage = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const start = total === 0 ? 0 : (data?.page ?? page) * PAGE_SIZE - PAGE_SIZE + 1;
  const end = Math.min((data?.page ?? page) * PAGE_SIZE, total);

  const toggleSeverity = (sev: Severity) => {
    setSeverities((prev) => (prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]));
  };

  const hasActiveFilters =
    severities.length > 0 ||
    band !== "all" ||
    shieldFilter !== "all" ||
    agentKey !== "all" ||
    debouncedQ.length > 0;

  const clearFilters = () => {
    setSeverities([]);
    setBand("all");
    setShieldFilter("all");
    setAgentKey("all");
    setSearch("");
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Findings</h2>
          <p className="text-xs text-muted-foreground">
            Bayesian confidence model · every finding carries a reproducible evidence chain
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {shieldedIds.size > 0 ? (
            <Badge
              variant="outline"
              className="gap-1.5 border-emerald-500/40 bg-emerald-500/10 font-mono text-[11px] text-emerald-400"
            >
              <ShieldCheck className="h-3 w-3" aria-hidden />
              {shieldedIds.size} shielded
            </Badge>
          ) : null}
          <Badge variant="outline" className="gap-1.5 bg-card/60 font-mono text-[11px] text-zinc-400">
            <Siren className="h-3 w-3 text-primary" aria-hidden />
            {formatNumber(total)} total
          </Badge>
        </div>
      </div>

      {/* Filters */}
      <div className="space-y-2.5 rounded-lg border bg-card/40 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Severity</span>
          {SEVERITY_ORDER.map((sev) => {
            const active = severities.includes(sev);
            return (
              <button
                key={sev}
                type="button"
                aria-pressed={active}
                onClick={() => toggleSeverity(sev)}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                  active
                    ? SEVERITY_STYLES[sev].badge
                    : "border-zinc-700/60 bg-zinc-900/40 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
                )}
              >
                {SEVERITY_STYLES[sev].label}
              </button>
            );
          })}
          <span className="mx-1 hidden h-4 w-px bg-zinc-800 sm:block" aria-hidden />
          <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Band</span>
          <button
            type="button"
            aria-pressed={band === "all"}
            onClick={() => setBand("all")}
            className={cn(
              "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
              band === "all"
                ? "border-primary/50 bg-primary/10 text-primary"
                : "border-zinc-700/60 bg-zinc-900/40 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
            )}
          >
            All bands
          </button>
          {(Object.keys(BAND_STYLES) as ConfidenceBand[]).map((b) => (
            <button
              key={b}
              type="button"
              aria-pressed={band === b}
              onClick={() => setBand(b)}
              title={BAND_STYLES[b].hint}
              className={cn(
                "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                band === b
                  ? BAND_STYLES[b].badge
                  : "border-zinc-700/60 bg-zinc-900/40 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
              )}
            >
              {BAND_STYLES[b].label}
            </button>
          ))}
          <span className="mx-1 hidden h-4 w-px bg-zinc-800 sm:block" aria-hidden />
          <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Defense</span>
          {(["all", "shielded", "unshielded"] as const).map((s) => (
            <button
              key={s}
              type="button"
              aria-pressed={shieldFilter === s}
              onClick={() => setShieldFilter(s)}
              className={cn(
                "rounded-full border px-2.5 py-1 text-[11px] font-medium capitalize transition-colors",
                shieldFilter === s
                  ? s === "shielded"
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                    : "border-zinc-500/60 bg-zinc-800 text-zinc-200"
                  : "border-zinc-700/60 bg-zinc-900/40 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
              )}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-0 flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" aria-hidden />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search title, target, CVE…"
              aria-label="Search findings"
              className="h-8 border-zinc-700/60 bg-zinc-900/40 pl-8 pr-8 text-xs"
            />
            {search.length > 0 ? (
              <button
                type="button"
                onClick={() => setSearch("")}
                aria-label="Clear search"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
              >
                <X className="h-3.5 w-3.5" aria-hidden />
              </button>
            ) : null}
          </div>
          <Select value={agentKey} onValueChange={(v) => setAgentKey(v)}>
            <SelectTrigger size="sm" className="w-[170px] border-zinc-700/60 bg-zinc-900/40 text-xs" aria-label="Filter by agent">
              <SelectValue placeholder="All agents" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All agents</SelectItem>
              {AGENT_KEYS.map((k) => (
                <SelectItem key={k} value={k} className="font-mono text-xs">
                  {k}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {hasActiveFilters ? (
            <Button variant="ghost" size="sm" onClick={clearFilters} className="h-8 gap-1.5 px-2.5 text-xs text-zinc-400">
              <X className="h-3 w-3" aria-hidden />
              Clear filters
            </Button>
          ) : null}
        </div>
      </div>

      {/* Results */}
      {isLoading ? (
        <ListSkeleton rows={6} />
      ) : isError ? (
        <ErrorState
          title="Failed to load findings"
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      ) : findings.length === 0 ? (
        <EmptyState
          icon={<Siren className="h-5 w-5" aria-hidden />}
          title={hasActiveFilters ? "No findings match the current filters" : "No findings yet"}
          description={
            hasActiveFilters
              ? "Adjust severity, band, agent or search terms to widen the result set."
              : "Findings appear here as scan agents confirm evidence above the reporting threshold."
          }
          action={
            hasActiveFilters ? (
              <Button variant="outline" size="sm" onClick={clearFilters}>
                Clear filters
              </Button>
            ) : undefined
          }
        />
      ) : (
        <>
          {/* table header (lg only) */}
          <div className="hidden lg:grid lg:grid-cols-[92px_minmax(0,1fr)_104px_140px_96px_64px] lg:gap-3 rounded-lg border border-border/60 bg-zinc-900/40 px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-zinc-500">
            <span>Severity</span>
            <span>Finding</span>
            <span>Agent</span>
            <span>Confidence</span>
            <span>Band</span>
            <span className="text-right">Detected</span>
          </div>

          <div className={cn("space-y-2 transition-opacity", isFetching && "opacity-60")}>
            {visibleFindings.map((f) => (
              <FindingRow
                key={f.id}
                finding={f}
                shielded={shieldedIds.has(f.id)}
                onOpen={() => openFinding(f.id)}
              />
            ))}
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between gap-3">
            <p className="font-mono text-[11px] text-zinc-500">
              {start}–{end} of {formatNumber(total)}
            </p>
            <div className="flex items-center gap-1.5">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || isFetching}
                aria-label="Previous page"
                className="h-8 gap-1 px-2.5"
              >
                <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
                Prev
              </Button>
              <span className="px-1 font-mono text-[11px] text-zinc-400" aria-live="polite">
                {page}/{lastPage}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage((p) => Math.min(lastPage, p + 1))}
                disabled={page >= lastPage || isFetching}
                aria-label="Next page"
                className="h-8 gap-1 px-2.5"
              >
                Next
                <ChevronRight className="h-3.5 w-3.5" aria-hidden />
              </Button>
            </div>
          </div>
        </>
      )}
      {isLoading ? <p className="sr-only" role="status">Loading findings…</p> : null}
    </div>
  );
}
