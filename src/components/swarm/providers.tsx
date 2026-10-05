"use client";

// ─── SwarmScan Providers: TanStack Query + Engine Socket bus ────────────────

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { io, type Socket } from "socket.io-client";
import type {
  EngineAgentUpdate,
  EngineAlertNew,
  EngineDriftNew,
  EngineEventNew,
  EngineFindingNew,
  EngineFirewallNew,
  EngineKilled,
  EngineMonitoringNew,
  EngineOobNew,
  EngineScanUpdate,
  EngineShardNew,
  EngineStats,
} from "@/lib/swarm/types";

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 4_000,
        refetchOnWindowFocus: false,
        retry: 1,
      },
    },
  });
}

// ─── Socket bus ──────────────────────────────────────────────────────────────

export type EngineEventName =
  | "scan:update"
  | "agent:update"
  | "finding:new"
  | "event:new"
  | "killed"
  | "engine:stats"
  | "oob:new"
  | "firewall:new"
  | "shard:new"
  | "monitoring:new"
  | "drift:new"
  | "alert:new";

export interface EngineEventPayloads {
  "scan:update": EngineScanUpdate;
  "agent:update": EngineAgentUpdate;
  "finding:new": EngineFindingNew;
  "event:new": EngineEventNew;
  killed: EngineKilled;
  "engine:stats": EngineStats;
  "oob:new": EngineOobNew;
  "firewall:new": EngineFirewallNew;
  "shard:new": EngineShardNew;
  "monitoring:new": EngineMonitoringNew;
  "drift:new": EngineDriftNew;
  "alert:new": EngineAlertNew;
}

export interface EngineSocketState {
  connected: boolean;
  stats: EngineStats | null;
  lastKilled: EngineKilled | null;
}

interface EngineSocketApi extends EngineSocketState {
  on: <E extends EngineEventName>(
    event: E,
    handler: (payload: EngineEventPayloads[E]) => void
  ) => () => void;
}

/**
 * Module-level handler registry. The SwarmScan shell mounts exactly one
 * SocketProvider, so a module singleton avoids reading refs during render
 * (react-hooks/refs) while keeping subscription identity stable.
 */
class HandlerRegistry {
  private map = new Map<EngineEventName, Set<(payload: never) => void>>();

  on(event: EngineEventName, handler: (payload: never) => void): () => void {
    let set = this.map.get(event);
    if (!set) {
      set = new Set();
      this.map.set(event, set);
    }
    set.add(handler);
    return () => {
      this.map.get(event)?.delete(handler);
    };
  }

  emit(event: EngineEventName, payload: unknown) {
    this.map.get(event)?.forEach((fn) => fn(payload as never));
  }
}

const registry = new HandlerRegistry();

const SocketContext = createContext<EngineSocketApi | null>(null);

function SocketProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState<EngineStats | null>(null);
  const [lastKilled, setLastKilled] = useState<EngineKilled | null>(null);

  useEffect(() => {
    // Gateway-compliant connection: relative path + XTransformPort query.
    const socket: Socket = io("/?XTransformPort=3003", {
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: 8,
      reconnectionDelay: 1000,
      timeout: 10000,
    });

    socket.on("connect", () => setConnected(true));
    socket.on("disconnect", () => setConnected(false));
    socket.on("engine:stats", (payload: EngineStats) => setStats(payload));
    socket.on("killed", (payload: EngineKilled) => setLastKilled(payload));

    // Fan engine events out to component subscribers via the registry.
    const events: EngineEventName[] = [
      "scan:update",
      "agent:update",
      "finding:new",
      "event:new",
      "oob:new",
      "firewall:new",
      "shard:new",
      "monitoring:new",
      "drift:new",
      "alert:new",
    ];
    const removers = events.map((evt) => {
      const handler = (payload: unknown) => registry.emit(evt, payload);
      socket.on(evt, handler as never);
      return () => socket.off(evt, handler as never);
    });

    return () => {
      removers.forEach((r) => r());
      socket.disconnect();
    };
  }, []);

  const api = useMemo<EngineSocketApi>(
    () => ({
      connected,
      stats,
      lastKilled,
      on: (event, handler) => registry.on(event, handler as (payload: never) => void),
    }),
    [connected, stats, lastKilled]
  );

  return (
    <SocketContext.Provider value={api}>{children}</SocketContext.Provider>
  );
}

export function useEngineSocket(): EngineSocketApi {
  const ctx = useContext(SocketContext);
  if (!ctx) throw new Error("useEngineSocket must be used within SwarmProviders");
  return ctx;
}

let browserClient: QueryClient | undefined;

function getQueryClient() {
  if (typeof window === "undefined") {
    return makeQueryClient();
  }
  return (browserClient ??= makeQueryClient());
}

export function SwarmProviders({ children }: { children: ReactNode }) {
  const queryClient = getQueryClient();
  return (
    <QueryClientProvider client={queryClient}>
      <SocketProvider>{children}</SocketProvider>
    </QueryClientProvider>
  );
}
