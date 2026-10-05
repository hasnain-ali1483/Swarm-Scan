"use client";

// ─── Live graph state — finding:new over the engine socket bus (Task 12-a) ──
// Wraps the stable useEngineSub("finding:new") subscription and derives
// everything the Graph Explorer's live mode needs:
//   · events       — the last findings streamed this session (cap 24, newest
//                    first) for the live feed strip
//   · pulseIds     — graph node ids currently pulsing on the canvas. For each
//                    incoming finding we pulse every node it relates to that
//                    EXISTS in the current GraphData: f:{findingId}, plus
//                    s:{scanId} and a:{scanId}:{agentKey} when present. Ids
//                    auto-clear after ~4.6s (3 ring reps of 1.5s + slack).
//   · offGraphCount — findings streamed since the last query whose f:{id} node
//                    is NOT in the current graph (drives the re-run nudge).
//   · pause/buffer  — when paused, incoming events buffer (no pulses); un-
//                    pausing merges them back so nothing is lost.
// There are NO client-side timers fabricating findings — the engine bus is the
// only source of truth.
//
// The feed/buffer/pause state lives in a module-level session cache so it
// survives Graph Explorer unmount/remount (view switches) within the page
// lifetime; a full page reload starts a fresh session. Pulses are ephemeral
// and stay per-mount.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AGENT_BY_KEY } from "@/lib/swarm/agents-catalog";
import type { GraphData, Severity } from "@/lib/swarm/types";
import { useEngineSub } from "@/components/swarm/overview/use-engine-sub";

/** One streamed finding:new event, normalized for the feed strip. */
export interface LiveFindingEvent {
  /** Session-local monotonic counter (stable ordering across pause merges). */
  seq: number;
  /** Wall-clock receive time (ms epoch) — feed timestamps. */
  receivedAt: number;
  findingId: string;
  scanId: string;
  agentKey: string;
  agentName: string;
  title: string;
  severity: Severity;
  /** 0–100 confidence as broadcast by the engine. */
  confidence: number;
}

const EVENT_CAP = 24;
const PULSE_CLEAR_MS = 4600;

// ── Module-level session cache (survives view switches, not reloads) ─────────
const session = {
  seq: 0,
  totalSeen: 0,
  paused: false,
  events: [] as LiveFindingEvent[],
  buffer: [] as LiveFindingEvent[],
  /** seq of the last event counted before the current graph arrived. */
  baseline: 0,
};

export interface UseLiveGraphResult {
  events: LiveFindingEvent[];
  /** Node ids currently pulsing (auto-clearing). */
  pulseIds: Set<string>;
  /** Findings streamed since the last query whose f:{id} is off-graph. */
  offGraphCount: number;
  isPaused: boolean;
  /** Events received while paused (shown on un-pause). */
  bufferedCount: number;
  /** Total finding:new events received this session (paused ones included). */
  totalSeen: number;
  toggle: () => void;
  clear: () => void;
  /** Manually fire a pulse on a node (feed-row click → select + pulse). */
  pulseNode: (nodeId: string) => void;
}

export function useLiveGraph(graphData: GraphData | null): UseLiveGraphResult {
  // Seeded from the session cache — a remount continues where it left off.
  const [events, setEvents] = useState<LiveFindingEvent[]>(session.events);
  const [pulseIds, setPulseIds] = useState<Set<string>>(new Set());
  const [isPaused, setIsPaused] = useState(session.paused);
  const [bufferedCount, setBufferedCount] = useState(session.buffer.length);
  const [totalSeen, setTotalSeen] = useState(session.totalSeen);

  const nodeIdsRef = useRef<Set<string>>(new Set());
  const pulseTimersRef = useRef(new Map<string, number>());

  // Current-graph node ids — memoized for the render path (offGraphCount),
  // mirrored into a ref for the socket-event handler path.
  const nodeIds = useMemo(
    () => new Set((graphData?.nodes ?? []).map((n) => n.id)),
    [graphData],
  );

  // Re-baseline the off-graph counter whenever a fresh query result lands
  // (the graph now reflects the DB) — the sanctioned adjust-state-during-
  // render pattern for "state that mirrors a prop" (no effect, no cascade).
  const [seenGraph, setSeenGraph] = useState<GraphData | null | undefined>(undefined);
  const [baselineSeq, setBaselineSeq] = useState(session.baseline);
  if (seenGraph !== graphData) {
    setSeenGraph(graphData);
    setBaselineSeq(session.seq);
  }

  // Mirror the node-id set for the handler path (effect-safe).
  useEffect(() => {
    nodeIdsRef.current = nodeIds;
  }, [nodeIds]);

  const addPulse = useCallback((ids: string[]) => {
    const liveIds = ids.filter((id) => nodeIdsRef.current.has(id));
    if (liveIds.length === 0) return;
    setPulseIds((cur) => {
      if (liveIds.every((id) => cur.has(id))) return cur; // timers still extended
      const next = new Set(cur);
      for (const id of liveIds) next.add(id);
      return next;
    });
    const timers = pulseTimersRef.current;
    for (const id of liveIds) {
      const prev = timers.get(id);
      if (prev !== undefined) window.clearTimeout(prev);
      const t = window.setTimeout(() => {
        timers.delete(id);
        setPulseIds((cur) => {
          if (!cur.has(id)) return cur;
          const next = new Set(cur);
          next.delete(id);
          return next;
        });
      }, PULSE_CLEAR_MS);
      timers.set(id, t);
    }
  }, []);

  // ── The one true source: the engine socket bus ─────────────────────────────
  useEngineSub("finding:new", ({ scanId, finding }) => {
    session.seq += 1;
    session.totalSeen += 1;
    const ev: LiveFindingEvent = {
      seq: session.seq,
      receivedAt: Date.now(),
      findingId: finding.id,
      scanId,
      agentKey: finding.agentKey,
      agentName: AGENT_BY_KEY[finding.agentKey]?.name ?? finding.agentKey,
      title: finding.title,
      severity: finding.severity,
      confidence: finding.confidence,
    };

    if (session.paused) {
      session.buffer = [ev, ...session.buffer].slice(0, EVENT_CAP);
      setBufferedCount(session.buffer.length);
      setTotalSeen(session.totalSeen);
      return; // paused → no pulses, row shows up on un-pause
    }

    session.events = [ev, ...session.events].slice(0, EVENT_CAP);
    setEvents(session.events);
    setTotalSeen(session.totalSeen);
    // Pulse every current-graph node this finding relates to.
    addPulse([`f:${finding.id}`, `s:${scanId}`, `a:${scanId}:${finding.agentKey}`]);
  });

  // ── Controls ───────────────────────────────────────────────────────────────
  const toggle = useCallback(() => {
    const next = !session.paused;
    session.paused = next;
    setIsPaused(next);
    if (!next && session.buffer.length > 0) {
      // Un-pause: merge the buffer back in (newest first, cap 24). No
      // retroactive pulses — the graph moment has passed.
      session.events = [...session.buffer, ...session.events]
        .sort((a, b) => b.seq - a.seq)
        .slice(0, EVENT_CAP);
      session.buffer = [];
      setBufferedCount(0);
      setEvents(session.events);
    }
  }, []);

  const clear = useCallback(() => {
    session.buffer = [];
    session.events = [];
    session.totalSeen = 0;
    session.baseline = session.seq;
    setBufferedCount(0);
    setEvents([]);
    setTotalSeen(0);
    setBaselineSeq(session.seq);
    for (const t of pulseTimersRef.current.values()) window.clearTimeout(t);
    pulseTimersRef.current.clear();
    setPulseIds(new Set());
  }, []);

  const pulseNode = useCallback(
    (nodeId: string) => {
      addPulse([nodeId]);
    },
    [addPulse]
  );

  // Clear any straggling pulse timers on unmount (pulses are ephemeral).
  useEffect(() => {
    const timers = pulseTimersRef.current;
    return () => {
      for (const t of timers.values()) window.clearTimeout(t);
      timers.clear();
    };
  }, []);

  // Off-graph count: events streamed AFTER the current graph arrived whose
  // finding node is not part of it (buffered ones join the count on merge).
  const offGraphCount = useMemo(() => {
    let count = 0;
    for (const ev of events) {
      if (ev.seq > baselineSeq && !nodeIds.has(`f:${ev.findingId}`)) count++;
    }
    return count;
  }, [events, baselineSeq, nodeIds]);

  return {
    events,
    pulseIds,
    offGraphCount,
    isPaused,
    bufferedCount,
    totalSeen,
    toggle,
    clear,
    pulseNode,
  };
}
