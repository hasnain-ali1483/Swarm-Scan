"use client";

// ─── Agent detail dialog — full spec, vertical FSM stepper, contracts ─────────

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { cn, formatNumber } from "@/lib/swarm/format";
import { ShieldAlert, ShieldCheck, Link2, GitCommitVertical, Swords, Zap, GitMerge } from "lucide-react";
import { SafetyBadge, UnorthodoxBadge, DynamicBadge, type RegistryAgent } from "./agent-card";
import { FUSION_RULES_VIEW, AGENT_BY_KEY } from "@/lib/swarm/agents-catalog";
import { BundleSection } from "./signing/bundle-section";

function StatCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-900/50 px-3 py-2">
      <div className="font-mono text-sm font-semibold text-zinc-100">{value}</div>
      <div className="mt-0.5 text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
    </div>
  );
}

/** Vertical FSM stepper with connected dots. */
function StateStepper({ states }: { states: string[] }) {
  return (
    <ol className="relative" aria-label="Agent FSM states in execution order">
      {states.map((state, i) => (
        <li key={state} className="relative flex gap-3 pb-4 last:pb-0">
          {i < states.length - 1 && (
            <span
              className="absolute left-[4.5px] top-4 h-[calc(100%-0.75rem)] w-px bg-zinc-700"
              aria-hidden
            />
          )}
          <span
            className={cn(
              "relative z-10 mt-1 h-2.5 w-2.5 shrink-0 rounded-full border-2",
              i === 0
                ? "border-primary bg-primary/30"
                : "border-zinc-600 bg-zinc-900"
            )}
            aria-hidden
          />
          <div className="min-w-0">
            <div className="font-mono text-xs text-zinc-200">{state}</div>
            <div className="mt-0.5 text-[11px] capitalize text-zinc-500">
              {i === 0 ? "entry · " : ""}
              {state.replace(/_/g, " ")}
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function AgentDetailDialog({
  agent,
  open,
  onOpenChange,
}: {
  agent: RegistryAgent | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  if (!agent) return null;
  const touching = agent.safetyClass === "data-touching";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto swarm-scroll bg-zinc-950/95">
        <DialogHeader>
          <div className="flex flex-wrap items-center gap-2 pr-6">
            <DialogTitle className="font-semibold tracking-tight">{agent.name}</DialogTitle>
            <Badge variant="outline" className="bg-zinc-900 px-1.5 font-mono text-[10px] text-zinc-400">
              v{agent.version}
            </Badge>
            <SafetyBadge safetyClass={agent.safetyClass} />
            <Badge variant="outline" className="border-zinc-700/70 bg-zinc-900/40 px-1.5 text-[10px] text-zinc-400">
              {agent.category}
            </Badge>
            <Badge
              variant="outline"
              className="border-primary/30 bg-primary/10 px-1.5 font-mono text-[10px] text-primary"
              title="DAG stage in the scan plan — parallel within stage, sequential across stages"
            >
              stage {agent.stage}
            </Badge>
            {agent.unorthodox && <UnorthodoxBadge tradecraft={agent.tradecraft} />}
            {agent.dynamic && <DynamicBadge spawnOnDesc={agent.spawnOnDesc} />}
          </div>
          <DialogDescription className="text-xs leading-relaxed text-zinc-400">
            {agent.description}
          </DialogDescription>
        </DialogHeader>

        {/* tradecraft callout — unorthodox family */}
        {agent.unorthodox && agent.tradecraft && (
          <div
            className="flex items-start gap-2.5 rounded-lg border border-rose-500/30 bg-rose-500/[0.06] p-3"
            role="note"
            aria-label="Tradecraft rationale"
          >
            <Swords className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden />
            <div>
              <div className="font-mono text-[10px] uppercase tracking-wider text-rose-400">
                tradecraft — why this hurts
              </div>
              <p className="mt-1 text-[12px] leading-relaxed text-zinc-300">{agent.tradecraft}</p>
            </div>
          </div>
        )}

        {/* spawn trigger — dynamic family */}
        {agent.dynamic && (
          <div
            className="flex items-start gap-2.5 rounded-lg border border-dashed border-fuchsia-500/35 bg-fuchsia-500/[0.05] p-3"
            role="note"
            aria-label="Runtime spawn trigger"
          >
            <Zap className="mt-0.5 h-4 w-4 shrink-0 text-fuchsia-400" aria-hidden />
            <div>
              <div className="font-mono text-[10px] uppercase tracking-wider text-fuchsia-400">
                dynamic agent — runtime spawn trigger
              </div>
              <p className="mt-1 text-[12px] leading-relaxed text-zinc-300">
                {agent.spawnOnDesc ?? "Runtime condition"}. Not part of the static plan — the agent
                sits <span className="text-fuchsia-300">dormant</span> and joins the scan mid-flight
                the moment this condition is observed, running in parallel with the active stage.
              </p>
            </div>
          </div>
        )}

        {/* fusion rulebook — FusionAgent only */}
        {agent.key === "fusion" && (
          <section aria-label="Cross-finding fusion rulebook" className="space-y-2">
            <h3 className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-zinc-400">
              <GitMerge className="h-3.5 w-3.5 text-fuchsia-400" aria-hidden />
              Fusion rulebook · {FUSION_RULES_VIEW.length} rules
            </h3>
            <div className="space-y-2">
              {FUSION_RULES_VIEW.map((rule) => (
                <div
                  key={rule.id}
                  className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="font-mono text-[10px] text-fuchsia-300">{rule.id}</code>
                    <Badge
                      variant="outline"
                      className="border-red-500/40 bg-red-500/10 px-1.5 text-[10px] uppercase text-red-400"
                    >
                      {rule.severity}
                    </Badge>
                  </div>
                  <div className="mt-1.5 text-[12px] font-medium leading-snug text-zinc-200">
                    {rule.name}
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-1.5">
                    {rule.requires.map((req, i) => (
                      <span key={`${rule.id}-${req.agentKey}-${req.category}`} className="flex items-center gap-1.5">
                        {i > 0 && <span className="font-mono text-[10px] text-zinc-600">+</span>}
                        <span
                          className="rounded-sm border border-zinc-700 bg-zinc-900/70 px-1.5 py-px font-mono text-[10px] text-zinc-300"
                          title={`${AGENT_BY_KEY[req.agentKey]?.name ?? req.agentKey} · component severity ≤ ${req.severityAtMost}`}
                        >
                          {req.agentKey}:{req.category}
                          <span className="text-zinc-600"> ≤{req.severityAtMost}</span>
                        </span>
                      </span>
                    ))}
                    <span className="ml-1 font-mono text-[10px] text-fuchsia-400/80">
                      → {rule.severity}
                    </span>
                  </div>
                  <p className="mt-2 text-[11px] leading-relaxed text-zinc-400">{rule.description}</p>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* stats */}
        <div className="grid grid-cols-3 gap-2">
          <StatCell label="runs" value={formatNumber(agent.runs)} />
          <StatCell label="findings" value={formatNumber(agent.findings)} />
          <StatCell
            label="avg confidence"
            value={agent.avgConfidence > 0 ? `${Math.round(agent.avgConfidence)}%` : "—"}
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {/* FSM stepper */}
          <section aria-label="FSM states">
            <h3 className="mb-3 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-zinc-400">
              <GitCommitVertical className="h-3.5 w-3.5 text-primary" aria-hidden />
              FSM states · {agent.states.length}
            </h3>
            <StateStepper states={agent.states} />
          </section>

          {/* contracts + guarantees */}
          <div className="space-y-4">
            <section aria-label="Message contracts">
              <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                <Link2 className="h-3.5 w-3.5 text-primary" aria-hidden />
                Contracts
              </h3>
              <div className="space-y-2">
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-600">
                    consumes
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {agent.consumes.map((c) => (
                      <span
                        key={c}
                        className="rounded-sm border border-zinc-800 bg-zinc-900/60 px-1.5 py-px font-mono text-[10px] text-zinc-400"
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-wider text-zinc-600">
                    emits
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {agent.emits.map((e) => (
                      <span
                        key={e}
                        className="rounded-sm border border-primary/25 bg-primary/10 px-1.5 py-px font-mono text-[10px] text-emerald-300"
                      >
                        {e}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            <section
              aria-label="Determinism and safety guarantees"
              className="space-y-2 rounded-lg border border-zinc-800 bg-zinc-900/40 p-3"
            >
              <div className="flex items-start gap-2 text-[11px] leading-relaxed text-zinc-300">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" aria-hidden />
                Idempotent &amp; replayable — same{" "}
                <code className="font-mono text-[10px] text-zinc-100">(target, seed, version)</code>{" "}
                ⇒ identical probe sequence.
              </div>
              <div className="flex items-start gap-2 text-[11px] leading-relaxed text-zinc-300">
                <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" aria-hidden />
                Evidence ledger append-only · hash-chained.
              </div>
              <div
                className={cn(
                  "flex items-start gap-2 rounded-md border p-2 text-[11px] leading-relaxed",
                  touching
                    ? "border-amber-500/30 bg-amber-500/8 text-amber-300"
                    : "border-emerald-500/30 bg-emerald-500/8 text-emerald-300"
                )}
              >
                {touching ? (
                  <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                ) : (
                  <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                )}
                {touching
                  ? "Data-touching agent — destructive payloads: denied. Every state-changing probe requires an explicit policy exception plus per-target ticketed approval."
                  : "Read-only agent — non-destructive probes only. No target state is modified."}
              </div>
            </section>

            <BundleSection agentKey={agent.key} releaseTag={`${agent.key}@${agent.version}`} />
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
