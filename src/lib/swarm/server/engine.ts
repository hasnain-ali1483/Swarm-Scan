// ─── Scan-engine execution plane HTTP client (server-to-server) ──────────────
// The engine runs as a mini-service on port 3003. Calls made here are
// backend→backend on localhost (allowed); the XTransformPort gateway rule
// only applies to browser-originated requests.

import type { EngineHealthResponse, EngineKillResponse } from "@/lib/swarm/types";

const ENGINE_BASE = process.env.SWARM_ENGINE_URL ?? "http://localhost:3003";
const ENGINE_TIMEOUT_MS = 2500;

export const ENGINE_UNREACHABLE =
  "Execution plane unreachable — is the scan-engine service running on :3003?";

export class EngineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EngineError";
  }
}

export interface EngineAgentLive {
  id?: string;
  agentKey: string;
  agentName: string;
  version: string;
  state: string;
  status: string;
  progress: number;
  requests: number;
  findings: number;
  startedAt?: string | null;
  endedAt?: string | null;
}

export interface EngineScanLive {
  scanId: string;
  target: string;
  status: string;
  progress: number;
  requestCount: number;
  agents: EngineAgentLive[];
}

export const ENGINE_DOWN_HEALTH: EngineHealthResponse = {
  ok: false,
  activeScans: 0,
  workers: 0,
  uptimeSec: 0,
  lastKillLatencyMs: null,
};

/** Fetch against the engine; throws EngineError on network failure or non-2xx. */
export async function engineFetch<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${ENGINE_BASE}${path}`, {
      ...init,
      signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS),
      cache: "no-store",
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new EngineError(ENGINE_UNREACHABLE);
  }
  if (!res.ok) {
    let message = `Engine returned HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body?.error) message = String(body.error);
    } catch {
      /* keep default message */
    }
    throw new EngineError(message);
  }
  return (await res.json()) as T;
}

/** GET /health — never throws; returns the graceful "down" shape on failure. */
export async function getEngineHealth(): Promise<EngineHealthResponse> {
  try {
    return await engineFetch<EngineHealthResponse>("/health");
  } catch {
    return { ...ENGINE_DOWN_HEALTH };
  }
}

/** GET /scans — never throws; returns [] on failure. */
export async function getEngineScans(): Promise<EngineScanLive[]> {
  try {
    const res = await engineFetch<{ scans: EngineScanLive[] }>("/scans");
    return Array.isArray(res?.scans) ? res.scans : [];
  } catch {
    return [];
  }
}

/** POST /kill — proxies the engine kill switch. */
export async function engineKill(scanId?: string): Promise<EngineKillResponse> {
  return engineFetch<EngineKillResponse>("/kill", {
    method: "POST",
    body: JSON.stringify(scanId ? { scanId } : {}),
  });
}
