"use client";

// ─── Agent registry card — catalog entry + live run stats ─────────────────────

import { Fragment } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, ShieldCheck, Swords, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn, formatNumber } from "@/lib/swarm/format";
import type { AgentCatalogEntry } from "@/lib/swarm/types";

export type RegistryAgent = AgentCatalogEntry & {
  runs: number;
  findings: number;
  avgConfidence: number;
};

export function SafetyBadge({
  safetyClass,
  className,
}: {
  safetyClass: AgentCatalogEntry["safetyClass"];
  className?: string;
}) {
  const touching = safetyClass === "data-touching";
  const Icon = touching ? ShieldAlert : ShieldCheck;
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 px-1.5 py-0 text-[10px] font-medium",
        touching
          ? "bg-amber-500/12 text-amber-400 border-amber-500/40"
          : "bg-emerald-500/12 text-emerald-400 border-emerald-500/40",
        className
      )}
      title={
        touching
          ? "Data-touching — probes may mutate target state; destructive payloads denied"
          : "Read-only — non-destructive probes only"
      }
    >
      <Icon className="h-3 w-3" aria-hidden />
      {safetyClass}
    </Badge>
  );
}

/** Unorthodox-family badge — attacker tradecraft outside the textbook canon. */
export function UnorthodoxBadge({ tradecraft }: { tradecraft?: string }) {
  return (
    <Badge
      variant="outline"
      className="gap-1 border-rose-500/40 bg-rose-500/10 px-1.5 py-0 text-[10px] font-medium text-rose-400"
      title={tradecraft ?? "Unorthodox tradecraft — not taught, what attackers actually run"}
    >
      <Swords className="h-3 w-3" aria-hidden />
      unorthodox
    </Badge>
  );
}

/** Dynamic-family badge — dormant until the runtime spawn trigger fires. */
export function DynamicBadge({ spawnOnDesc }: { spawnOnDesc?: string }) {
  return (
    <Badge
      variant="outline"
      className="gap-1 border-fuchsia-500/40 bg-fuchsia-500/10 px-1.5 py-0 text-[10px] font-medium text-fuchsia-400"
      title={spawnOnDesc ? `Spawns at runtime — ${spawnOnDesc}` : "Spawns at runtime when its trigger fires"}
    >
      <Zap className="h-3 w-3" aria-hidden />
      dynamic
    </Badge>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div
      className="h-1 w-full overflow-hidden rounded-full bg-zinc-800"
      role="progressbar"
      aria-valuenow={Math.round(pct)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Average confidence ${pct.toFixed(1)}%`}
    >
      <div
        className={cn(
          "h-full rounded-full transition-all duration-500",
          pct >= 85 ? "bg-emerald-500" : pct >= 60 ? "bg-amber-500" : "bg-zinc-500"
        )}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

/** Horizontal mini-stepper of the agent's FSM states. */
function FsmMiniStepper({ states }: { states: string[] }) {
  return (
    <div
      className="flex flex-wrap items-center gap-x-1 gap-y-1"
      aria-label="Finite-state machine states"
    >
      {states.map((state, i) => (
        <Fragment key={state}>
          {i > 0 && (
            <span
              className="h-px w-2 shrink-0 bg-gradient-to-r from-primary/40 to-zinc-700"
              aria-hidden
            />
          )}
          <span
            className={cn(
              "rounded-sm border px-1.5 py-px font-mono text-[10px] leading-4",
              i === 0
                ? "border-primary/40 bg-primary/10 text-primary"
                : "border-zinc-700/80 bg-zinc-900/70 text-zinc-300"
            )}
            title={i === 0 ? "entry state" : `state ${i + 1} of ${states.length}`}
          >
            {state}
          </span>
        </Fragment>
      ))}
    </div>
  );
}

function ContractChips({
  label,
  items,
  tone,
}: {
  label: string;
  items: string[];
  tone: "muted" | "emerald";
}) {
  if (!items.length) return null;
  return (
    <div className="flex items-start gap-1.5">
      <span className="pt-px font-mono text-[10px] uppercase tracking-wider text-zinc-600">
        {label}
      </span>
      <div className="flex flex-wrap gap-1">
        {items.map((item) => (
          <span
            key={item}
            className={cn(
              "rounded-sm border px-1.5 py-px font-mono text-[10px] leading-4",
              tone === "emerald"
                ? "border-primary/25 bg-primary/10 text-emerald-300"
                : "border-zinc-800 bg-zinc-900/60 text-zinc-500"
            )}
          >
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

export function AgentCard({
  agent,
  index,
  onSelect,
}: {
  agent: RegistryAgent;
  index: number;
  onSelect: (agent: RegistryAgent) => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.045, 0.5), duration: 0.3, ease: "easeOut" }}
    >
      <button
        type="button"
        onClick={() => onSelect(agent)}
        aria-haspopup="dialog"
        aria-label={`Open ${agent.name} details`}
        className="group flex h-full w-full flex-col rounded-lg border border-zinc-800 bg-card/60 p-4 text-left transition-colors hover:border-primary/40 hover:bg-card focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/60"
      >
        {/* header */}
        <div className="flex items-start justify-between gap-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-zinc-100">{agent.name}</span>
            <Badge
              variant="outline"
              className="bg-zinc-900/80 px-1.5 font-mono text-[10px] text-zinc-400"
            >
              v{agent.version}
            </Badge>
          </div>
          <SafetyBadge safetyClass={agent.safetyClass} />
        </div>

        <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
          <Badge
            variant="outline"
            className="border-zinc-700/70 bg-zinc-900/40 px-1.5 text-[10px] text-zinc-400"
          >
            {agent.category}
          </Badge>
          {agent.unorthodox && <UnorthodoxBadge tradecraft={agent.tradecraft} />}
          {agent.dynamic && <DynamicBadge spawnOnDesc={agent.spawnOnDesc} />}
        </div>

        {agent.dynamic && agent.spawnOnDesc && (
          <div className="mt-2 rounded-md border border-dashed border-fuchsia-500/25 bg-fuchsia-500/[0.04] px-2 py-1.5 font-mono text-[10px] leading-snug text-fuchsia-300/90">
            <Zap className="mr-1 inline h-3 w-3 align-[-1px]" aria-hidden />
            spawns mid-scan — {agent.spawnOnDesc}
          </div>
        )}

        <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-zinc-400">
          {agent.description}
        </p>

        {/* stats */}
        <div className="mt-3 space-y-1.5">
          <div className="flex items-baseline justify-between font-mono text-[11px] text-zinc-400">
            <span>
              <span className="text-zinc-200">{formatNumber(agent.runs)}</span> runs
            </span>
            <span aria-hidden>·</span>
            <span>
              <span className="text-zinc-200">{formatNumber(agent.findings)}</span> findings
            </span>
            <span aria-hidden>·</span>
            <span>
              avg conf{" "}
              <span
                className={cn(
                  agent.avgConfidence >= 85
                    ? "text-emerald-400"
                    : agent.avgConfidence >= 60
                      ? "text-amber-400"
                      : "text-zinc-300"
                )}
              >
                {agent.avgConfidence > 0 ? `${Math.round(agent.avgConfidence)}%` : "—"}
              </span>
            </span>
          </div>
          <ConfidenceBar value={agent.avgConfidence} />
        </div>

        {/* FSM states */}
        <div className="mt-3 border-t border-zinc-800/80 pt-3">
          <FsmMiniStepper states={agent.states} />
        </div>

        {/* contracts */}
        <div className="mt-3 space-y-1.5 border-t border-zinc-800/80 pt-3">
          <ContractChips label="consumes" items={agent.consumes} tone="muted" />
          <ContractChips label="emits" items={agent.emits} tone="emerald" />
        </div>
      </button>
    </motion.div>
  );
}
