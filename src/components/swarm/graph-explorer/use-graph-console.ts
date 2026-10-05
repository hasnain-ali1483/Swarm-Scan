"use client";

// ─── GraphQL console state hook (Task 9-a) ───────────────────────────────────
// Owns the editable query text, the last execution result, and the derived
// GraphData that feeds the canvas. Runs the default graph query once on mount.
// Non-graph queries keep the last rendered graph on the canvas (the console
// result pane shows their JSON instead).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, type GqlError, type GqlResponse, type GraphData } from "@/lib/swarm/types";
import { DEFAULT_QUERY } from "./presets";

export interface ConsoleResult {
  ranQuery: string;
  ts: number;
  data?: GqlResponse["data"];
  errors?: GqlError[];
  latencyMs?: number;
  transportError?: string;
  /** Last successfully returned graph (carried forward across non-graph queries). */
  graph: GraphData | null;
  /** Increments each time a NEW graph arrives — used to key the canvas remount. */
  graphSeq: number;
}

export function extractGraph(data: unknown): GraphData | null {
  if (data !== null && typeof data === "object" && "graph" in data) {
    const g = (data as { graph?: unknown }).graph;
    if (g !== null && typeof g === "object" && "nodes" in g && "edges" in g && "stats" in g) {
      return g as GraphData;
    }
  }
  return null;
}

export function useGraphConsole() {
  const [query, setQuery] = useState(DEFAULT_QUERY);
  const [result, setResult] = useState<ConsoleResult | null>(null);
  const bootRef = useRef(false);
  const lastGraphRef = useRef<GraphData | null>(null);
  const graphSeqRef = useRef(0);

  const mutation = useMutation({
    mutationFn: (source: string) =>
      api<GqlResponse>("/api/graphql", { method: "POST", body: JSON.stringify({ query: source }) }),
    onSuccess: (res, source) => {
      const graph = extractGraph(res.data);
      if (graph) {
        lastGraphRef.current = graph;
        graphSeqRef.current += 1;
      }
      setResult({
        ranQuery: source,
        ts: Date.now(),
        data: res.data,
        errors: res.errors,
        latencyMs: res.latencyMs,
        graph: lastGraphRef.current,
        graphSeq: graphSeqRef.current,
      });
    },
    onError: (err, source) =>
      setResult({
        ranQuery: source,
        ts: Date.now(),
        transportError: err instanceof Error ? err.message : "Request failed",
        graph: lastGraphRef.current,
        graphSeq: graphSeqRef.current,
      }),
  });

  const { mutate } = mutation;

  // Auto-run the default graph query once on mount so the canvas has data.
  useEffect(() => {
    if (bootRef.current) return;
    bootRef.current = true;
    mutate(DEFAULT_QUERY);
  }, [mutate]);

  const run = useCallback(
    (source?: string) => {
      const q = (source ?? query).trim();
      if (!q) return;
      mutate(q);
    },
    [query, mutate],
  );

  const applyPreset = useCallback(
    (presetQuery: string) => {
      setQuery(presetQuery);
      mutate(presetQuery);
    },
    [mutate],
  );

  const graphData = useMemo(() => result?.graph ?? null, [result]);

  return {
    query,
    setQuery,
    result,
    running: mutation.isPending,
    run,
    applyPreset,
    graphData,
    graphSeq: result?.graphSeq ?? 0,
  };
}
