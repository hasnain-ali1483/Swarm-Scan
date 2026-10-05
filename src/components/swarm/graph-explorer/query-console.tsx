"use client";

// ─── GraphQL query console (Task 9-a) ────────────────────────────────────────
// Editable query + preset chips + Run → POST /api/graphql. Pretty-prints the
// result JSON (latency badge, styled errors with line:column), and feeds the
// canvas whenever the executed query returns a `graph` field.

import { motion } from "framer-motion";
import { Loader2, Play, Terminal } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { GqlError } from "@/lib/swarm/types";
import { cn } from "@/lib/swarm/format";
import type { ConsoleResult } from "./use-graph-console";
import { PRESETS } from "./presets";

export interface QueryConsoleProps {
  query: string;
  setQuery: (q: string) => void;
  result: ConsoleResult | null;
  running: boolean;
  onRun: (source?: string) => void;
  onPreset: (presetQuery: string) => void;
  graphRendered: boolean;
  /** Live mode active (socket bus streaming, not paused). */
  liveMode: boolean;
}

export function QueryConsole({
  query,
  setQuery,
  result,
  running,
  onRun,
  onPreset,
  graphRendered,
  liveMode,
}: QueryConsoleProps) {
  const hasErrors = (result?.errors?.length ?? 0) > 0;

  return (
    <Card className="rounded-xl">
      <CardHeader className="px-4 pb-3 sm:px-5">
        <CardTitle className="flex flex-wrap items-center gap-2.5 text-sm">
          <Terminal className="h-4 w-4 text-primary" aria-hidden />
          Query console
          <Badge
            variant="outline"
            className="swarm-mono text-[10px] text-primary border-primary/40"
          >
            POST /api/graphql
          </Badge>
          {result?.latencyMs !== undefined && !result.transportError && (
            <Badge
              variant="outline"
              className={cn(
                "swarm-mono text-[10px]",
                hasErrors
                  ? "text-red-400 border-red-500/40"
                  : "text-emerald-400 border-emerald-500/40",
              )}
            >
              {result.latencyMs.toFixed(1)} ms
            </Badge>
          )}
        </CardTitle>
        <CardDescription className="text-xs">
          The console drives the graph — any query returning a{" "}
          <code className="font-mono text-[11px] text-primary">graph</code> field renders on the
          canvas.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 px-4 pb-4 sm:px-5">
        {/* preset chips */}
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Preset queries">
          {PRESETS.map((p) => {
            const active = p.query === query;
            return (
              <Button
                key={p.key}
                size="sm"
                variant="outline"
                className={cn(
                  "h-6 rounded-full px-2.5 text-[11px]",
                  active
                    ? "border-primary/50 bg-primary/15 text-primary hover:text-primary"
                    : "text-zinc-400",
                )}
                onClick={() => onPreset(p.query)}
                aria-pressed={active}
              >
                {p.label}
              </Button>
            );
          })}
        </div>

        {/* query editor */}
        <label htmlFor="gql-query-input" className="sr-only">
          GraphQL query text
        </label>
        <textarea
          id="gql-query-input"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
              e.preventDefault();
              onRun();
            }
          }}
          rows={10}
          spellCheck={false}
          aria-label="GraphQL query editor"
          className="swarm-scroll swarm-mono w-full resize-y rounded-md border border-border bg-zinc-950/70 p-3 text-[11.5px] leading-relaxed text-zinc-200 shadow-none outline-none placeholder:text-zinc-600 focus-visible:border-primary/50 focus-visible:ring-1 focus-visible:ring-primary/40"
          placeholder="query { graph { nodes { id kind label } } }"
        />

        <div className="flex items-center justify-between gap-3">
          <Button
            size="sm"
            onClick={() => onRun()}
            disabled={running || query.trim().length === 0}
            className="gap-1.5"
            aria-label="Run GraphQL query"
          >
            {running ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                Running…
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5" aria-hidden />
                Run query
              </>
            )}
          </Button>
          <span className="font-mono text-[10px] text-zinc-600">⌘/Ctrl + Enter</span>
        </div>

        {/* result */}
        <div aria-live="polite">
          {result === null ? (
            <p className="rounded-md border border-dashed px-3 py-4 text-center text-xs text-zinc-500">
              No query executed yet.
            </p>
          ) : (
            <motion.div
              key={result.ts}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2 }}
              className="space-y-2"
            >
              {result.transportError ? (
                <div
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-xs text-red-400"
                >
                  <p className="font-medium">Request failed</p>
                  <p className="mt-1 break-words font-mono text-[11px] text-red-400/80">
                    {result.transportError}
                  </p>
                </div>
              ) : hasErrors ? (
                <div
                  role="alert"
                  className="rounded-md border border-destructive/50 bg-destructive/5 p-3"
                >
                  <p className="text-xs font-medium text-red-400">GraphQL errors</p>
                  <ul className="mt-1.5 space-y-1">
                    {result.errors?.map((e: GqlError, i: number) => (
                      <li
                        key={i}
                        className="break-words font-mono text-[11px] leading-relaxed text-red-400/90"
                      >
                        <span aria-hidden>✗ </span>
                        {e.message}
                        {e.locations && e.locations.length > 0 && (
                          <span className="text-red-400/60">
                            {" "}
                            (line {e.locations[0].line}, col {e.locations[0].column})
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="rounded-md border border-border bg-zinc-950/70">
                  {graphRendered && (
                    <p className="border-b border-border px-3 py-1.5 font-mono text-[10px] text-emerald-400">
                      → graph returned · rendered on canvas
                    </p>
                  )}
                  <pre className="swarm-scroll swarm-mono max-h-64 overflow-auto p-3 text-[10.5px] leading-relaxed text-zinc-300">
                    {JSON.stringify(result.data, null, 2)}
                  </pre>
                </div>
              )}
            </motion.div>
          )}
        </div>

        {/* live subscription footer — documents the honest transport story:
            the graph reacts to finding:new over the socket bus while queries
            themselves stay plain POST /api/graphql request/response. */}
        <p
          className={cn(
            "swarm-mono border-t border-border pt-2.5 text-[10px] leading-relaxed",
            liveMode ? "text-zinc-500" : "text-zinc-600",
          )}
        >
          {liveMode
            ? "live: finding:new → node pulses (transport: socket.io bus)"
            : "live: paused — finding:new events buffer on the bus"}
        </p>
      </CardContent>
    </Card>
  );
}
