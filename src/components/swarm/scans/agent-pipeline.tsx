"use client";

// ─── Agent pipeline (scan detail centerpiece) ────────────────────────────────
// DAG stages 0..5 rendered as vertical sections with a connector rail. Each
// agent card shows FSM state stepper, live progress and request/finding stats.
// Agents excluded by the scan profile render as dimmed "skipped" cards.

import { motion } from "framer-motion";
import {
  Check,
  Circle,
  Loader2,
  Minus,
  ShieldAlert,
  X,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { AGENT_BY_KEY } from "@/lib/swarm/agents-catalog";
import { cn } from "@/lib/swarm/format";
import type { AgentRun, AgentRunStatus } from "@/lib/swarm/types";
import { agentsInStage, STAGES, STAGE_LABELS } from "./stages";

const RUN_STATUS_ICON: Record<AgentRunStatus, { icon: LucideIcon; className: string; spin?: boolean }> = {
  dormant: { icon: Zap, className: "text-fuchsia-400" },
  pending: { icon: Circle, className: "text-zinc-500" },
  running: { icon: Loader2, className: "text-emerald-500", spin: true },
  done: { icon: Check, className: "text-emerald-500" },
  blocked: { icon: ShieldAlert, className: "text-amber-500" },
  skipped: { icon: Minus, className: "text-zinc-500" },
  killed: { icon: X, className: "text-red-500" },
};

function FsmDots({
  states,
  current,
  status,
}: {
  states: string[];
  current: number;
  status: AgentRunStatus;
}) {
  return (
    <div className="flex items-center" aria-label="FSM state progression">
      {states.map((state, i) => {
        const done = status === "done" || i < current;
        const isCurrent = i === current && status !== "done";
        return (
          <span key={state} className="flex items-center" title={state}>
            {i > 0 && <span className="h-px w-1.5 bg-zinc-700" aria-hidden />}
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                status === "killed" && i <= current
                  ? "bg-red-500"
                  : status === "blocked" && i === current
                    ? "bg-amber-500 swarm-pulse"
                    : isCurrent
                      ? "bg-primary swarm-pulse"
                      : done
                        ? "bg-primary/70"
                        : "bg-zinc-700"
              )}
              aria-hidden
            />
          </span>
        );
      })}
    </div>
  );
}

function AgentRunCard({ run, index }: { run: AgentRun; index: number }) {
  const catalog = AGENT_BY_KEY[run.agentKey];
  const states = catalog?.states ?? [];
  const currentIdx = Math.max(0, states.indexOf(run.state));
  const meta = RUN_STATUS_ICON[run.status] ?? RUN_STATUS_ICON.pending;
  const Icon = meta.icon;
  const done = run.status === "done";
  const blocked = run.status === "blocked";
  const dormant = run.status === "dormant";

  const card = (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, delay: Math.min(index * 0.03, 0.3), ease: "easeOut" }}
    >
      <Card
        className={cn(
          "gap-2 rounded-lg px-3 py-3 transition-colors",
          blocked && "border-amber-500/40 bg-amber-500/5",
          dormant && "border-dashed border-fuchsia-500/30 bg-fuchsia-500/[0.02]",
          run.status === "running" && "border-emerald-500/25 bg-emerald-500/[0.03]"
        )}
      >
        <div className="flex items-center gap-2">
          <Icon
            className={cn("h-3.5 w-3.5 shrink-0", meta.className, meta.spin && "animate-spin")}
            aria-hidden
          />
          <span className="truncate text-[13px] font-medium text-zinc-100">
            {run.agentName}
          </span>
          <span className="shrink-0 rounded border border-zinc-700 bg-zinc-800/40 px-1 py-px font-mono text-[9px] text-zinc-500">
            v{run.version}
          </span>
          <span
            className={cn(
              "ml-auto shrink-0 text-[10px] font-semibold uppercase tracking-wider",
              meta.className
            )}
            aria-label={`agent status ${run.status}`}
          >
            {run.status}
          </span>
        </div>

        <div className="truncate font-mono text-[11px] text-muted-foreground" title={run.state}>
          {done ? "✓ " : dormant ? "⌁ " : "▸ "}
          {run.state}
        </div>

        {states.length > 0 && !dormant && (
          <FsmDots states={states} current={currentIdx} status={run.status} />
        )}

        {dormant ? (
          <div className="font-mono text-[10px] text-fuchsia-400/80">
            dynamic — awaiting trigger: {catalog?.spawnOnDesc ?? "runtime condition"}
          </div>
        ) : (
          <div
            className="h-1 overflow-hidden rounded-full bg-muted"
            role="progressbar"
            aria-valuenow={Math.round(run.progress)}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`${run.agentName} progress`}
          >
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500",
                run.status === "killed"
                  ? "bg-red-500"
                  : blocked
                    ? "bg-amber-500"
                    : done
                      ? "bg-emerald-500/70"
                      : "bg-primary"
              )}
              style={{ width: `${Math.max(0, Math.min(100, run.progress))}%` }}
            />
          </div>
        )}

        <div className="flex items-center justify-between font-mono text-[10px] text-zinc-500">
          <span>req {run.requests.toLocaleString("en-US")}</span>
          <span className={cn(run.findings > 0 && "text-amber-400")}>
            findings {run.findings}
          </span>
        </div>
      </Card>
    </motion.div>
  );

  if (blocked) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{card}</TooltipTrigger>
        <TooltipContent>
          Policy denied: data-touching class requires approval
        </TooltipContent>
      </Tooltip>
    );
  }
  if (dormant) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{card}</TooltipTrigger>
        <TooltipContent>
          Dynamic agent — spawns mid-scan when its runtime trigger fires:
          {" "}{catalog?.spawnOnDesc ?? "runtime condition"}
        </TooltipContent>
      </Tooltip>
    );
  }
  return card;
}

function SkippedAgentCard({ agentKey }: { agentKey: string }) {
  const agent = AGENT_BY_KEY[agentKey];
  if (!agent) return null;
  const dynamic = agent.dynamic === true;
  return (
    <Card
      className={cn(
        "gap-1.5 rounded-lg border-dashed bg-muted/10 px-3 py-3 opacity-45",
        dynamic && "border-fuchsia-500/25 bg-fuchsia-500/[0.02]"
      )}
    >
      <div className="flex items-center gap-2">
        {dynamic ? (
          <Zap className="h-3.5 w-3.5 shrink-0 text-fuchsia-400/70" aria-hidden />
        ) : (
          <Minus className="h-3.5 w-3.5 shrink-0 text-zinc-600" aria-hidden />
        )}
        <span className="truncate text-[13px] font-medium text-zinc-400">
          {agent.name}
        </span>
        <span className="shrink-0 rounded border border-zinc-800 px-1 py-px font-mono text-[9px] text-zinc-600">
          v{agent.version}
        </span>
      </div>
      <div
        className={cn(
          "text-[10px] uppercase tracking-wider",
          dynamic ? "text-fuchsia-400/70" : "text-zinc-600"
        )}
        title={dynamic ? agent.spawnOnDesc : undefined}
      >
        {dynamic
          ? "dynamic — spawns at runtime when triggered"
          : "skipped — not in plan"}
      </div>
    </Card>
  );
}

export function AgentPipeline({
  scanId,
  agentRuns,
}: {
  scanId: string;
  agentRuns: AgentRun[];
}) {
  const runByKey = new Map(agentRuns.map((r) => [r.agentKey, r]));
  const runIndexByKey = new Map(agentRuns.map((r, i) => [r.agentKey, i]));
  const activeCount = agentRuns.length;

  return (
    <section aria-label="Agent pipeline" className="relative">
      <div className="absolute bottom-2 left-[7px] top-2 w-px bg-border" aria-hidden />
      {STAGES.map((stage) => {
        const stageAgents = agentsInStage(stage);
        const planned = stageAgents.filter((a) => runByKey.has(a.key));
        const doneCount = planned.filter((a) => runByKey.get(a.key)?.status === "done").length;
        return (
          <div key={stage} className="relative mb-5 pl-7 last:mb-0">
            <span
              className={cn(
                "absolute left-0 top-1 h-3.5 w-3.5 rounded-full border-2",
                planned.length > 0 && doneCount === planned.length
                  ? "border-primary bg-primary/40"
                  : planned.length > 0
                    ? "border-primary/70 bg-background swarm-pulse"
                    : "border-zinc-700 bg-background"
              )}
              aria-hidden
            />
            <header className="mb-2.5 flex flex-wrap items-baseline gap-2">
              <h3 className="text-[13px] font-semibold">
                Stage {stage}
                <span className="ml-1.5 font-normal text-muted-foreground">
                  — {STAGE_LABELS[stage]}
                </span>
              </h3>
              <span className="font-mono text-[10px] text-zinc-600">
                {planned.length > 0
                  ? `${doneCount}/${planned.length} done`
                  : "not in plan"}
              </span>
            </header>
            {planned.length > 0 && (
              <div className="grid gap-2.5 sm:grid-cols-2 2xl:grid-cols-3">
                {stageAgents.map((agent) => {
                  const run = runByKey.get(agent.key);
                  if (run) {
                    return (
                      <AgentRunCard
                        key={agent.key}
                        run={run}
                        index={runIndexByKey.get(agent.key) ?? 0}
                      />
                    );
                  }
                  return <SkippedAgentCard key={agent.key} agentKey={agent.key} />;
                })}
              </div>
            )}
            {planned.length === 0 && (
              <p className="rounded-lg border border-dashed px-3 py-2 font-mono text-[11px] text-zinc-700">
                stage skipped — no agents from this stage in scan plan {scanId.slice(0, 8)}
              </p>
            )}
          </div>
        );
      })}
      <p className="sr-only">
        {activeCount} agents in this scan plan across {STAGES.length} DAG stages.
      </p>
    </section>
  );
}
