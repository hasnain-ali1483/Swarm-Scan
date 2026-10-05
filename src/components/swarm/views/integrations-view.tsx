"use client";

// ─── Integrations view — 47-connector catalog browser ────────────────────────
// Search + category chips + connected-only over the full catalog, grouped into
// category sections. Each card opens the guardrail-centric connector dialog.

import { useMemo, useState } from "react";
import { Link2, RotateCcw, Search, X } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/swarm/format";
import {
  INTEGRATION_CATEGORY_LABELS,
  INTEGRATION_CATEGORY_ORDER,
} from "@/lib/swarm/integrations-catalog";
import type { IntegrationCategory, IntegrationItem } from "@/lib/swarm/types";
import { IntegrationCard } from "@/components/swarm/integrations/integration-card";
import { IntegrationDialog } from "@/components/swarm/integrations/integration-dialog";
import { CATEGORY_META } from "@/components/swarm/integrations/integration-meta";
import { useIntegrationMutations, useIntegrations } from "@/components/swarm/integrations/use-integrations";
import { CiGatesStrip } from "@/components/swarm/ci-gates/ci-gates-strip";

const SKELETON_COUNT = 9;

export function IntegrationsView() {
  const { data, isLoading, isError, error, refetch, isRefetching } = useIntegrations();
  const { toggle } = useIntegrationMutations();

  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<IntegrationCategory | "all">("all");
  const [connectedOnly, setConnectedOnly] = useState(false);
  const [configuringId, setConfiguringId] = useState<string | null>(null);
  const [configSession, setConfigSession] = useState(0);

  const integrations = useMemo<IntegrationItem[]>(() => data?.integrations ?? [], [data]);
  const total = integrations.length;

  // Live item for the open dialog — re-derived from the cache so guardrails,
  // stats and configSet refresh in place while the dialog stays open.
  const configuring = useMemo(
    () => integrations.find((i) => i.id === configuringId) ?? null,
    [integrations, configuringId]
  );

  // Truthful counts — "connected" means enabled AND verified (server-derived
  // connState; the old `enabled` flag alone could never prove verification).
  const connectedCount = integrations.filter((i) => i.connState === "connected").length;
  const stateCounts = useMemo(() => {
    const counts = {
      connected: 0,
      unverified: 0,
      failed: 0,
      not_configured: 0,
      disabled: 0,
    };
    for (const item of integrations) counts[item.connState] += 1;
    return counts;
  }, [integrations]);

  const guardrailCount = integrations.reduce((sum, item) => {
    const g = item.guardrails;
    let n = 0;
    if (g.rateLimitPerMin) n++;
    if (g.requiresApproval) n++;
    if (g.scopeEnforced) n++;
    if (g.dedupeByEvidence) n++;
    if (g.pinnedVersion) n++;
    if (g.dataMinimization) n++;
    if (g.readOnly) n++;
    return sum + n;
  }, 0);

  const categoryCounts = useMemo(() => {
    const map = new Map<IntegrationCategory, { total: number; connected: number }>();
    for (const category of INTEGRATION_CATEGORY_ORDER) map.set(category, { total: 0, connected: 0 });
    for (const item of integrations) {
      const entry = map.get(item.category);
      if (entry) {
        entry.total++;
        if (item.connState === "connected") entry.connected++;
      }
    }
    return map;
  }, [integrations]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return integrations.filter((item) => {
      if (activeCategory !== "all" && item.category !== activeCategory) return false;
      if (connectedOnly && item.connState !== "connected") return false;
      if (query) {
        const haystack = [item.name, item.key, item.description, ...item.cautions]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });
  }, [integrations, search, activeCategory, connectedOnly]);

  const grouped = useMemo(() => {
    const map = new Map<IntegrationCategory, IntegrationItem[]>();
    for (const category of INTEGRATION_CATEGORY_ORDER) map.set(category, []);
    for (const item of filtered) {
      const list = map.get(item.category);
      if (list) list.push(item);
      else map.set(item.category, [item]);
    }
    return map;
  }, [filtered]);

  const categoriesWithItems = INTEGRATION_CATEGORY_ORDER.filter(
    (c) => (categoryCounts.get(c)?.total ?? 0) > 0
  ).length;

  const hasActiveFilters = search.trim() !== "" || activeCategory !== "all" || connectedOnly;
  const busy = toggle.isPending;

  return (
    <div className="mx-auto w-full max-w-[1600px] px-4 py-6 lg:px-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="text-lg font-semibold tracking-tight">Integrations</h2>
        <p className="flex items-center gap-1.5 text-[11px] text-zinc-500">
          <Link2 className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden />
          Every connector documents the mistakes teams make — and the server-enforced guardrail
          that prevents each one.
        </p>
      </header>

      {/* summary strip — truthful state breakdown, not just an on/off count */}
      <div className="mt-4 flex flex-col gap-3 rounded-lg border border-zinc-800 bg-card/60 px-4 py-3 lg:flex-row lg:items-center">
        <span className="whitespace-nowrap font-mono text-sm">
          <span className="text-primary">{connectedCount}</span>
          <span className="text-zinc-500"> / {total} verified &amp; live</span>
        </span>
        <div
          className="h-1.5 min-w-16 flex-1 overflow-hidden rounded-full bg-zinc-800 lg:min-w-32"
          role="progressbar"
          aria-valuenow={total ? connectedCount : 0}
          aria-valuemin={0}
          aria-valuemax={total}
          aria-label={`${connectedCount} of ${total} connectors connected`}
        >
          <div
            className="h-full rounded-full bg-primary transition-all duration-500"
            style={{ width: `${total ? (connectedCount / total) * 100 : 0}%` }}
          />
        </div>
        <div
          className="flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[10px]"
          role="group"
          aria-label="Connection state breakdown"
        >
          <span className="flex items-center gap-1 text-zinc-500" title="Enabled AND verified — live">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden />
            {stateCounts.connected} live
          </span>
          <span className="flex items-center gap-1 text-zinc-500" title="Config complete, awaiting a passing test">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" aria-hidden />
            {stateCounts.unverified} unverified
          </span>
          <span className="flex items-center gap-1 text-zinc-500" title="Last connection test failed">
            <span className="h-1.5 w-1.5 rounded-full bg-red-500" aria-hidden />
            {stateCounts.failed} failed
          </span>
          <span className="flex items-center gap-1 text-zinc-500" title="Verified configuration, switched off">
            <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" aria-hidden />
            {stateCounts.disabled} off
          </span>
          <span className="flex items-center gap-1 text-zinc-500" title="Required fields missing">
            <span className="h-1.5 w-1.5 rounded-full bg-zinc-600" aria-hidden />
            {stateCounts.not_configured} unset
          </span>
        </div>
        <span className="whitespace-nowrap font-mono text-[10px] text-zinc-600">
          {isLoading
            ? "syncing…"
            : `${categoriesWithItems} categories · ${guardrailCount} guardrails enforced`}
        </span>
      </div>

      {/* release gates strip — benchmark corpus CI gating agent-registry publishes */}
      <CiGatesStrip />

      {/* error */}
      {isError && (
        <Alert variant="destructive" className="mt-4">
          <AlertTitle>Could not load the connector catalog</AlertTitle>
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
      )}

      {/* toolbar — search + category chips + connected only */}
      {!isError && (
        <div className="mt-6 flex flex-col gap-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600"
                aria-hidden
              />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={`Search ${total || 47} connectors — name, key or caution…`}
                className="h-9 pl-8 pr-8 text-xs"
                aria-label="Search connectors by name, key or caution"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch("")}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-zinc-600 transition-colors hover:text-zinc-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label="Clear search"
                >
                  <X className="h-3.5 w-3.5" aria-hidden />
                </button>
              )}
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Switch
                id="integrations-connected-only"
                checked={connectedOnly}
                onCheckedChange={setConnectedOnly}
                aria-label="Show connected connectors only"
              />
              <Label
                htmlFor="integrations-connected-only"
                className="cursor-pointer text-xs text-zinc-400"
              >
                Connected only
              </Label>
            </div>
          </div>

          <div
            role="group"
            aria-label="Filter connectors by category"
            className="flex flex-wrap gap-1.5"
          >
            <button
              type="button"
              onClick={() => setActiveCategory("all")}
              aria-pressed={activeCategory === "all"}
              className={cn(
                "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
                activeCategory === "all"
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-zinc-800 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
              )}
            >
              All
              <span className="font-mono text-[10px] opacity-70">
                {connectedCount}/{total}
              </span>
            </button>
            {INTEGRATION_CATEGORY_ORDER.map((category) => {
              const counts = categoryCounts.get(category);
              if (!counts || counts.total === 0) return null;
              const active = activeCategory === category;
              const CategoryIcon = CATEGORY_META[category].icon;
              return (
                <button
                  key={category}
                  type="button"
                  onClick={() => setActiveCategory(active ? "all" : category)}
                  aria-pressed={active}
                  className={cn(
                    "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[11px] transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
                    active
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-zinc-800 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
                  )}
                >
                  <CategoryIcon className="h-3 w-3" aria-hidden />
                  {INTEGRATION_CATEGORY_LABELS[category]}
                  <span className="font-mono text-[10px] opacity-70">
                    {counts.connected}/{counts.total}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* catalog sections */}
      {isLoading ? (
        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: SKELETON_COUNT }, (_, i) => (
            <Skeleton key={i} className="h-48 rounded-lg" />
          ))}
        </div>
      ) : (
        <div className="mt-5 space-y-8">
          {INTEGRATION_CATEGORY_ORDER.map((category) => {
            const items = grouped.get(category) ?? [];
            if (items.length === 0) return null;
            const meta = CATEGORY_META[category];
            return (
              <section key={category} aria-labelledby={`integrations-${category}-heading`}>
                <div className="mb-3 flex items-center gap-2.5">
                  <meta.icon
                    className={cn("h-3.5 w-3.5 shrink-0", meta.text)}
                    aria-hidden
                  />
                  <h3
                    id={`integrations-${category}-heading`}
                    className="text-xs font-medium uppercase tracking-widest text-zinc-400"
                  >
                    {INTEGRATION_CATEGORY_LABELS[category]}
                  </h3>
                  <span className="hidden text-[10px] text-zinc-600 md:inline">
                    {meta.blurb}
                  </span>
                  <span className="font-mono text-[11px] text-zinc-600">{items.length}</span>
                  <div
                    className="h-px flex-1 bg-gradient-to-r from-zinc-800 to-transparent"
                    aria-hidden
                  />
                </div>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {items.map((integration, i) => (
                    <IntegrationCard
                      key={integration.id}
                      integration={integration}
                      index={i}
                      busy={busy}
                      onToggle={(item, enabled) => toggle.mutate({ id: item.id, enabled })}
                      onConfigure={(item) => {
                        setConfiguringId(item.id);
                        setConfigSession((s) => s + 1);
                      }}
                    />
                  ))}
                </div>
              </section>
            );
          })}

          {total === 0 && (
            <div className="rounded-lg border border-dashed border-zinc-800 p-12 text-center">
              <p className="text-sm text-zinc-300">No connectors available</p>
              <p className="mt-1 text-xs text-zinc-500">
                The catalog service did not return any integrations — retry in a moment.
              </p>
            </div>
          )}

          {total > 0 && filtered.length === 0 && (
            <div className="rounded-lg border border-dashed border-zinc-800 p-12 text-center">
              <p className="text-sm text-zinc-300">No connectors match your filters</p>
              <p className="mt-1 text-xs text-zinc-500">
                Try a different search term, category or the connected-only toggle.
              </p>
              {hasActiveFilters && (
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-3 gap-1.5"
                  onClick={() => {
                    setSearch("");
                    setActiveCategory("all");
                    setConnectedOnly(false);
                  }}
                >
                  <X className="h-3.5 w-3.5" aria-hidden />
                  Clear filters
                </Button>
              )}
            </div>
          )}
        </div>
      )}

      {/* connector dialog — remounted per session so form state hydrates cleanly */}
      <IntegrationDialog
        key={`integration-dialog-${configSession}`}
        integration={configuring}
        open={!!configuringId}
        onOpenChange={(open) => !open && setConfiguringId(null)}
      />
    </div>
  );
}
