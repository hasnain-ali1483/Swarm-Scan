"use client";

// ─── Integration catalog card — icon, verified switch, agent benefit, chips ──
// The switch is honest: it can only be flipped ON when the server says the
// connector is verifiable (verified·off). Unverified / failed / unconfigured
// connectors show a locked switch whose tooltip explains the exact next step,
// and the status label is the server-derived connState — never a guess.

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Bot, Download, Lock, Send, Settings2, TriangleAlert } from "lucide-react";
import { motion } from "framer-motion";
import { INTEGRATION_CATEGORY_LABELS } from "@/lib/swarm/integrations-catalog";
import { cn, formatNumber, timeAgo } from "@/lib/swarm/format";
import type { IntegrationItem } from "@/lib/swarm/types";
import { CONN_STATE_META } from "./conn-state";
import { metaFor } from "./integration-meta";

export function IntegrationCard({
  integration,
  index,
  onToggle,
  onConfigure,
  busy,
}: {
  integration: IntegrationItem;
  index: number;
  onToggle: (integration: IntegrationItem, enabled: boolean) => void;
  onConfigure: (integration: IntegrationItem) => void;
  busy?: boolean;
}) {
  const meta = metaFor(integration.key);
  const Icon = meta.icon;
  const switchId = `integration-enabled-${integration.id}`;
  const outbound = integration.direction === "outbound";
  const state = CONN_STATE_META[integration.connState];
  const StateIcon = state.icon;
  const live = integration.connState === "connected";
  const switchLocked = !live && !state.canEnable;

  return (
    <motion.article
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(index * 0.04, 0.4), duration: 0.28, ease: "easeOut" }}
      className={cn(
        "flex flex-col rounded-lg border bg-card/60 p-4 transition-colors",
        live
          ? "border-emerald-500/25 hover:border-emerald-500/40"
          : integration.connState === "failed"
            ? "border-red-500/20 hover:border-red-500/35"
            : "border-zinc-800/60 opacity-80 hover:opacity-100"
      )}
      aria-label={`Integration ${integration.name}`}
    >
      {/* Row 1 — identity + verified connection switch */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <span
            className={cn(
              "flex h-9 w-9 shrink-0 items-center justify-center rounded-md border",
              meta.tint
            )}
            aria-hidden
          >
            <Icon className="h-4.5 w-4.5" />
          </span>
          <div className="min-w-0">
            <h3 className="truncate text-sm font-medium text-zinc-100">{integration.name}</h3>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1">
              <Badge
                variant="outline"
                className="border-zinc-700/70 bg-zinc-900/40 px-1.5 text-[10px] text-zinc-400"
              >
                {INTEGRATION_CATEGORY_LABELS[integration.category] ?? integration.category}
              </Badge>
              <span
                className="flex items-center gap-1 font-mono text-[10px] text-zinc-400"
                title={outbound ? "Outbound — findings leave the control plane" : "Inbound — external context flows in"}
              >
                {outbound ? (
                  <Send className="h-2.5 w-2.5" aria-hidden />
                ) : (
                  <Download className="h-2.5 w-2.5" aria-hidden />
                )}
                {outbound ? "dispatches" : "enriches"}
              </span>
            </div>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1.5">
          <TooltipProvider delayDuration={150}>
            <Tooltip>
              <TooltipTrigger asChild>
                {/* span wrapper keeps the tooltip anchored when the switch is disabled */}
                <span className="inline-flex">
                  <Switch
                    id={switchId}
                    checked={integration.enabled}
                    disabled={busy || switchLocked}
                    onCheckedChange={(checked) => onToggle(integration, checked)}
                    aria-label={`${integration.enabled ? "Disconnect" : "Connect"} ${integration.name}`}
                  />
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-56 border-zinc-800 bg-zinc-950/95 text-[11px] leading-4 text-zinc-300">
                {switchLocked ? (
                  <span className="flex items-start gap-1.5">
                    <Lock className="mt-0.5 h-3 w-3 shrink-0 text-amber-400" aria-hidden />
                    {state.explanation}
                  </span>
                ) : live ? (
                  "Verified and streaming — click to disconnect."
                ) : (
                  "Configuration verified — click to connect."
                )}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
          <Label
            htmlFor={switchId}
            className={cn("flex items-center gap-1.5 text-[11px]", state.text)}
          >
            <span className={cn("h-1.5 w-1.5 rounded-full", state.dot)} aria-hidden />
            {state.label}
          </Label>
        </div>
      </div>

      {/* Row 2 — why connect */}
      <p className="mt-3 min-h-8 text-xs leading-relaxed text-zinc-400 line-clamp-2">
        {integration.description}
      </p>

      {/* Row 3 — how it helps the agent */}
      <p className="mt-2.5 flex items-start gap-1.5 text-[11px] leading-4 text-emerald-400/90">
        <Bot className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" aria-hidden />
        <span className="line-clamp-1">
          <span className="font-medium text-emerald-500/80">Agent:</span>{" "}
          {integration.agentBenefit}
        </span>
      </p>

      {/* Row 4 — footer: cautions, verification, throughput, configure */}
      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-zinc-800/80 pt-3">
        {integration.cautions.length > 0 && (
          <TooltipProvider delayDuration={150}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  className="flex cursor-help items-center gap-1 rounded-sm border border-amber-500/25 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-400/90 transition-colors hover:border-amber-500/40 hover:text-amber-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  aria-label={`View ${integration.cautions.length} common mistakes for ${integration.name}`}
                >
                  <TriangleAlert className="h-2.5 w-2.5" aria-hidden />
                  {integration.cautions.length} cautions
                </button>
              </TooltipTrigger>
              <TooltipContent side="top" className="w-72 border-zinc-800 bg-zinc-950/95 p-3">
                <p className="text-[10px] font-medium uppercase tracking-wider text-amber-400">
                  Common mistakes
                </p>
                <ul className="mt-1.5 space-y-1">
                  {integration.cautions.map((caution) => (
                    <li key={caution} className="flex items-start gap-1.5 text-[11px] leading-4 text-zinc-300">
                      <TriangleAlert className="mt-0.5 h-2.5 w-2.5 shrink-0 text-amber-400/80" aria-hidden />
                      {caution}
                    </li>
                  ))}
                </ul>
                <p className="mt-2 border-t border-zinc-800 pt-1.5 text-[10px] text-zinc-400">
                  Each mistake maps to a server-enforced guardrail — see the connector page.
                </p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
        <TooltipProvider delayDuration={150}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span
                className={cn(
                  "flex cursor-help items-center gap-1 whitespace-nowrap text-[10px]",
                  state.text
                )}
              >
                <StateIcon className="h-2.5 w-2.5" aria-hidden />
                {integration.lastTest
                  ? `${integration.lastTest.ok ? "verified" : "failed"} ${timeAgo(integration.lastTest.at)}`
                  : "never tested"}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top" className="max-w-64 border-zinc-800 bg-zinc-950/95 text-[11px] leading-4 text-zinc-300">
              {integration.lastTest
                ? `${integration.lastTest.ok ? "Passed" : "Failed"} — ${integration.lastTest.detail}`
                : "No connection test on record — the server blocks enabling until one passes."}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
        <span className="font-mono text-[10px] text-zinc-500" aria-hidden>
          {outbound
            ? `↦ ${formatNumber(integration.stats.dispatched)} dispatched`
            : `↤ synced ${integration.lastSyncAt ? timeAgo(integration.lastSyncAt) : "never"}`}
        </span>
        <Button
          variant="outline"
          size="sm"
          onClick={() => onConfigure(integration)}
          className="ml-auto h-7 gap-1.5 px-2.5 text-xs"
          aria-label={`Configure ${integration.name}`}
        >
          <Settings2 className="h-3.5 w-3.5" aria-hidden />
          Configure
        </Button>
      </div>
    </motion.article>
  );
}
