"use client";

// ─── Agents view — registry of all agents, grouped by DAG stage ───────────────

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bot, Search, Swords, Wifi, WifiOff, Zap } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/swarm/format";
import { api, type AgentRegistryResponse } from "@/lib/swarm/types";
import { AGENTS_CATALOG, MAX_STAGE } from "@/lib/swarm/agents-catalog";
import { AgentCard, type RegistryAgent } from "@/components/swarm/agents/agent-card";
import { SigningSummary } from "@/components/swarm/agents/signing/signing-summary";
import { AgentDetailDialog } from "@/components/swarm/agents/agent-detail-dialog";

const CATEGORIES = [
  "recon",
  "osint",
  "discovery",
  "perimeter",
  "injection",
  "smuggling",
  "routing",
  "disclosure",
  "secrets",
  "client",
  "cache",
  "files",
  "authz",
  "credentials",
  "api",
  "crypto",
  "cloud",
  "logic",
  "side-channel",
  "correlation",
  "fusion",
  "pivot",
  "continuous",
  "evasion",
] as const;

const STAGE_TITLES = [
  "Stage 0 · Recon & OSINT",
  "Stage 1 · Fingerprint & Perimeter",
  "Stage 2 · Discovery, Routing & Secrets",
  "Stage 3 · Exploitation & Poisoning",
  "Stage 4 · Auth, Identity, Crypto & Cloud",
  "Stage 5 · Correlation, Fusion & Post",
];

type SafetyFilter = "all" | "read-only" | "data-touching";
type FamilyFilter = "all" | "classic" | "unorthodox" | "dynamic";

const ZEROED_STATS = { runs: 0, findings: 0, avgConfidence: 0 };

export function AgentsView() {
  const [category, setCategory] = useState<string>("all");
  const [safety, setSafety] = useState<SafetyFilter>("all");
  const [family, setFamily] = useState<FamilyFilter>("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<RegistryAgent | null>(null);

  // Live per-agent stats; catalog renders optimistically while loading.
  const { data, isLoading, isError } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api<AgentRegistryResponse>("/api/agents"),
  });

  const agents = useMemo<RegistryAgent[]>(() => {
    if (!data?.agents?.length) {
      return AGENTS_CATALOG.map((a) => ({ ...a, ...ZEROED_STATS }));
    }
    const byKey = new Map(data.agents.map((a) => [a.key, a]));
    const catalogMerged = AGENTS_CATALOG.map<RegistryAgent>((c) => {
      const live = byKey.get(c.key);
      byKey.delete(c.key);
      return live
        ? { ...c, ...live, runs: live.runs ?? 0, findings: live.findings ?? 0, avgConfidence: live.avgConfidence ?? 0 }
        : { ...c, ...ZEROED_STATS };
    });
    // Any API-only agents not present in the static catalog.
    return [...catalogMerged, ...(byKey.size ? [...byKey.values()] : [])];
  }, [data]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return agents.filter((a) => {
      if (category !== "all" && a.category !== category) return false;
      if (safety !== "all" && a.safetyClass !== safety) return false;
      if (family !== "all") {
        if (family === "dynamic" && a.dynamic !== true) return false;
        if (family === "unorthodox" && a.unorthodox !== true) return false;
        if (family === "classic" && (a.dynamic || a.unorthodox)) return false;
      }
      if (q && !`${a.name} ${a.key}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [agents, category, safety, family, search]);

  const stages = useMemo(
    () =>
      Array.from({ length: MAX_STAGE + 1 }, (_, stage) => ({
        stage,
        agents: filtered.filter((a) => a.stage === stage),
      })).filter((s) => s.agents.length > 0),
    [filtered]
  );

  const liveChip = isLoading ? (
    <Badge variant="outline" className="gap-1.5 bg-card/60 font-mono text-[10px] text-zinc-400">
      <span className="h-1.5 w-1.5 rounded-full bg-zinc-500 swarm-pulse" aria-hidden />
      syncing live stats…
    </Badge>
  ) : isError ? (
    <Badge
      variant="outline"
      className="gap-1.5 border-amber-500/40 bg-amber-500/10 font-mono text-[10px] text-amber-400"
      title="GET /api/agents unavailable — rendering the static catalog without live run stats"
    >
      <WifiOff className="h-3 w-3" aria-hidden />
      live stats unavailable · catalog mode
    </Badge>
  ) : (
    <Badge
      variant="outline"
      className="gap-1.5 border-primary/30 bg-primary/10 font-mono text-[10px] text-primary"
    >
      <Wifi className="h-3 w-3" aria-hidden />
      live stats
    </Badge>
  );

  const unorthodoxCount = agents.filter((a) => a.unorthodox).length;
  const dynamicCount = agents.filter((a) => a.dynamic).length;

  return (
    <div className="px-4 lg:px-6 py-6 mx-auto w-full max-w-[1600px]">
      {/* header */}
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold tracking-tight">Agent Registry</h2>
          <Badge
            variant="outline"
            className="gap-1.5 border-primary/30 bg-primary/10 font-mono text-[11px] text-primary"
          >
            <Bot className="h-3 w-3" aria-hidden />
            {agents.length} agents
          </Badge>
          <Badge
            variant="outline"
            className="gap-1.5 border-rose-500/40 bg-rose-500/10 font-mono text-[11px] text-rose-400"
            title="Attacker tradecraft outside the textbook canon — what real intrusions run"
          >
            <Swords className="h-3 w-3" aria-hidden />
            {unorthodoxCount} unorthodox
          </Badge>
          <Badge
            variant="outline"
            className="gap-1.5 border-fuchsia-500/40 bg-fuchsia-500/10 font-mono text-[11px] text-fuchsia-400"
            title="Dormant until their runtime spawn trigger fires — join the scan mid-flight"
          >
            <Zap className="h-3 w-3" aria-hidden />
            {dynamicCount} dynamic
          </Badge>
          {liveChip}
        </div>
        {/* safety legend */}
        <div className="flex items-center gap-4 text-xs text-zinc-400" aria-label="Safety class legend">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-500" aria-hidden />
            read-only
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-amber-500" aria-hidden />
            data-touching
          </span>
        </div>
      </header>

      {/* filter row */}
      <div className="mt-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div
          className="flex flex-wrap items-center gap-1.5"
          role="group"
          aria-label="Filter agents by category"
        >
          {(["all", ...CATEGORIES] as string[]).map((cat) => {
            const active = category === cat;
            const count = cat === "all" ? agents.length : agents.filter((a) => a.category === cat).length;
            return (
              <button
                key={cat}
                type="button"
                onClick={() => setCategory(cat)}
                aria-pressed={active}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px] transition-colors",
                  active
                    ? "border-primary/40 bg-primary/15 text-primary"
                    : "border-zinc-800 bg-zinc-900/40 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
                )}
              >
                {cat === "all" ? "All" : cat}
                <span className="ml-1 font-mono text-[10px] opacity-60">{count}</span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2">
          {/* family toggle */}
          <div
            className="flex items-center rounded-md border border-zinc-800 bg-zinc-900/40 p-0.5"
            role="group"
            aria-label="Filter agents by family"
          >
            {(["all", "classic", "unorthodox", "dynamic"] as FamilyFilter[]).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFamily(f)}
                aria-pressed={family === f}
                className={cn(
                  "rounded px-2 py-1 text-[11px] transition-colors",
                  family === f
                    ? f === "unorthodox"
                      ? "bg-rose-500/15 text-rose-400"
                      : f === "dynamic"
                        ? "bg-fuchsia-500/15 text-fuchsia-400"
                        : "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300"
                )}
              >
                {f === "all" ? "All families" : f}
              </button>
            ))}
          </div>
          {/* safety class toggle */}
          <div
            className="flex items-center rounded-md border border-zinc-800 bg-zinc-900/40 p-0.5"
            role="group"
            aria-label="Filter agents by safety class"
          >
            {(["all", "read-only", "data-touching"] as SafetyFilter[]).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSafety(s)}
                aria-pressed={safety === s}
                className={cn(
                  "rounded px-2 py-1 text-[11px] transition-colors",
                  safety === s
                    ? s === "data-touching"
                      ? "bg-amber-500/15 text-amber-400"
                      : s === "read-only"
                        ? "bg-emerald-500/15 text-emerald-400"
                        : "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300"
                )}
              >
                {s === "all" ? "All classes" : s}
              </button>
            ))}
          </div>
          {/* search */}
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500"
              aria-hidden
            />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search name / key…"
              aria-label="Search agents by name or key"
              className="h-8 w-full pl-8 font-mono text-xs sm:w-56"
            />
          </div>
        </div>
      </div>

      {/* supply-chain strip */}
      <div className="mt-4">
        <SigningSummary />
      </div>

      {/* stage-grouped grid */}
      <div className="mt-6 space-y-8">
        {stages.map(({ stage, agents: stageAgents }) => (
          <section key={stage} aria-labelledby={`stage-${stage}-heading`}>
            <div className="mb-3 flex items-center gap-3">
              <h3
                id={`stage-${stage}-heading`}
                className="font-mono text-xs font-medium text-primary"
              >
                {STAGE_TITLES[stage] ?? `Stage ${stage}`}
              </h3>
              <span className="text-[11px] text-zinc-500">
                {stageAgents.length} agent{stageAgents.length === 1 ? "" : "s"} · parallel within
                stage
              </span>
              <div className="h-px flex-1 bg-gradient-to-r from-zinc-800 to-transparent" aria-hidden />
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
              {stageAgents.map((agent, i) => (
                <AgentCard key={agent.key} agent={agent} index={i} onSelect={setSelected} />
              ))}
            </div>
          </section>
        ))}

        {stages.length === 0 && (
          <div className="rounded-lg border border-dashed border-zinc-800 p-10 text-center">
            <p className="text-sm text-zinc-300">No agents match the current filters</p>
            <p className="mt-1 text-xs text-zinc-500">
              Adjust the category, safety class, or search query.
            </p>
            <button
              type="button"
              onClick={() => {
                setCategory("all");
                setSafety("all");
                setSearch("");
              }}
              className="mt-3 text-xs text-primary underline-offset-4 hover:underline"
            >
              Reset filters
            </button>
          </div>
        )}
      </div>

      {/* hydration skeleton hint (initial SSR paint) */}
      {isLoading && agents.length === 0 && (
        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-56 rounded-lg" />
          ))}
        </div>
      )}

      <AgentDetailDialog
        agent={selected}
        open={!!selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </div>
  );
}
