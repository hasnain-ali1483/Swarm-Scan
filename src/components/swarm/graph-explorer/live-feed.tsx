"use client";

// ─── Live finding feed strip (Task 12-a) ────────────────────────────────────
// The last 8 finding:new events received on the engine socket bus, animated
// in with framer-motion (slide + fade + a ~2s fresh-row glow). Clicking a row
// selects its finding node on the canvas when the graph has it, otherwise it
// deep-links into the Findings view. Purely presentational — all state lives
// in use-live-graph.ts; the ONLY event source is the real engine bus.

import { AnimatePresence, motion } from "framer-motion";
import { Pause, Play, Radio, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import type { LiveFindingEvent } from "./use-live-graph";

const MAX_ROWS = 8;

function feedTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export interface LiveFeedProps {
  events: LiveFindingEvent[];
  totalSeen: number;
  offGraphCount: number;
  isPaused: boolean;
  bufferedCount: number;
  /** Socket bus connection state (from useEngineSocket). */
  connected: boolean;
  onToggle: () => void;
  onClear: () => void;
  onRowClick: (ev: LiveFindingEvent) => void;
}

export function LiveFeed({
  events,
  totalSeen,
  offGraphCount,
  isPaused,
  bufferedCount,
  connected,
  onToggle,
  onClear,
  onRowClick,
}: LiveFeedProps) {
  const rows = events.slice(0, MAX_ROWS);

  return (
    <Card className="rounded-xl gap-3">
      <CardContent className="space-y-2.5 px-4 py-4 sm:px-5">
        {/* header: LIVE badge · counter · pause · clear */}
        <div className="flex flex-wrap items-center gap-2">
          <Badge
            variant="outline"
            className={cn(
              "swarm-mono gap-1.5 border-emerald-500/40 px-2 py-0.5 text-[10px] font-semibold tracking-widest",
              isPaused ? "border-zinc-700 text-zinc-400" : "text-emerald-400",
            )}
            aria-label={
              isPaused
                ? "Live feed paused"
                : connected
                  ? "Live feed streaming from the engine socket bus"
                  : "Live feed waiting for the engine bus to connect"
            }
          >
            <span
              aria-hidden
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                isPaused
                  ? "bg-zinc-500"
                  : connected
                    ? "swarm-pulse bg-emerald-400 text-emerald-400"
                    : "bg-zinc-600",
              )}
            />
            {isPaused ? "PAUSED" : "LIVE"}
          </Badge>
          <span className="flex items-baseline gap-1.5">
            <span className="swarm-mono text-xs font-semibold tabular-nums text-zinc-200">
              {totalSeen}
            </span>
            <span className="text-[10px] text-zinc-500">
              findings streamed{isPaused && bufferedCount > 0 ? ` · ${bufferedCount} buffered` : ""}
            </span>
          </span>
          <span className="ml-auto flex items-center gap-1">
            <Button
              size="sm"
              variant="ghost"
              className="h-6 w-6 p-0 text-zinc-400 hover:text-zinc-200"
              onClick={onToggle}
              aria-pressed={isPaused}
              aria-label={isPaused ? "Resume live feed" : "Pause live feed"}
              title={isPaused ? "Resume — buffered rows will appear" : "Pause — events keep buffering"}
            >
              {isPaused ? (
                <Play className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <Pause className="h-3.5 w-3.5" aria-hidden />
              )}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-6 w-6 p-0 text-zinc-400 hover:text-zinc-200"
              onClick={onClear}
              disabled={totalSeen === 0}
              aria-label="Clear live feed"
              title="Clear this session's feed"
            >
              <X className="h-3.5 w-3.5" aria-hidden />
            </Button>
          </span>
        </div>

        {/* the log itself */}
        <div
          role="log"
          aria-live="polite"
          aria-label="Live finding feed — newest finding:new events from the engine bus"
          className="min-h-[92px]"
        >
          {rows.length === 0 ? (
            <div className="flex items-center gap-3 rounded-lg border border-dashed bg-card/30 px-3 py-5">
              <Radio
                className="h-4 w-4 shrink-0 text-zinc-500"
                aria-hidden
              />
              <p className="text-xs leading-relaxed text-zinc-500">
                Listening to the event bus — findings pulse the graph as scans run.
              </p>
            </div>
          ) : (
            <ul className="space-y-1">
              <AnimatePresence initial={false}>
                {rows.map((ev) => {
                  const sev = SEVERITY_STYLES[ev.severity];
                  return (
                    <motion.li
                      key={ev.findingId}
                      layout="position"
                      initial={{ opacity: 0, x: -14 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 10, transition: { duration: 0.18 } }}
                      transition={{ duration: 0.35, ease: "easeOut" }}
                    >
                      <button
                        type="button"
                        onClick={() => onRowClick(ev)}
                        className="group relative block w-full rounded-md px-2 py-1.5 text-left transition-colors hover:bg-zinc-800/50 focus-visible:bg-zinc-800/50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/50"
                        aria-label={`Finding: ${ev.title} — ${ev.severity}, confidence ${ev.confidence} percent, from ${ev.agentName}. Activate to inspect.`}
                      >
                        {/* fresh-row glow: ~2s emerald tint fading out */}
                        <motion.span
                          aria-hidden
                          className="pointer-events-none absolute inset-0 rounded-md bg-emerald-400/[0.07]"
                          initial={{ opacity: 1 }}
                          animate={{ opacity: 0 }}
                          transition={{ duration: 2, ease: "easeOut" }}
                        />
                        <span className="relative flex items-center gap-2">
                          <span
                            className={cn("h-2 w-2 shrink-0 rounded-full", sev.dot)}
                            aria-hidden
                          />
                          <span className="min-w-0 flex-1">
                            <span className="block truncate text-xs leading-tight text-zinc-200 group-hover:text-zinc-50">
                              {ev.title}
                            </span>
                            <span className="swarm-mono mt-0.5 block truncate text-[10px] leading-tight text-zinc-500">
                              → {ev.agentName} ·{" "}
                              <span className="tabular-nums text-zinc-400">
                                {ev.confidence}%
                              </span>{" "}
                              · {feedTime(ev.receivedAt)}
                            </span>
                          </span>
                          <span
                            className={cn(
                              "swarm-mono shrink-0 text-[10px] font-semibold uppercase tracking-wide",
                              sev.text,
                            )}
                          >
                            {ev.severity.slice(0, 4)}
                          </span>
                        </span>
                      </button>
                    </motion.li>
                  );
                })}
              </AnimatePresence>
            </ul>
          )}
        </div>

        {/* a11y summary */}
        <span className="sr-only" aria-live="polite">
          {totalSeen} findings streamed, {offGraphCount} off-graph
        </span>
      </CardContent>
    </Card>
  );
}
