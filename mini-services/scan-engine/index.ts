// ─── SwarmScan scan-engine — execution plane (port 3003, hardcoded) ──────────
//
// Independent Node mini-service (run with tsx). Two planes share one HTTP server:
//   • socket.io bus (path "/") — required by the Caddy gateway rule, the
//     browser connects via io("/?XTransformPort=3003")
//   • plain JSON HTTP API    — /health, /scans, POST /start, POST /kill
//
// NOTE on coexistence: engine.io's attach() claims every request whose URL
// starts with the configured path — with path "/" that is EVERY request
// (engine.io/build/server.js: `path === req.url.slice(0, path.length)`).
// We therefore wrap io.engine.handleRequest and divert our API paths to the
// plain HTTP router; everything else (polling/websocket engine.io traffic)
// keeps flowing to engine.io untouched.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Server } from "socket.io";
import { ScanEngine } from "./lib/engine";
import { detectTools } from "./lib/tools";
import { log, logError } from "./lib/log";

// Cache external-tool detection (nuclei/nmap/httpx/…) for the /health surface.
let toolsCache: Awaited<ReturnType<typeof detectTools>> | null = null;
async function toolStatus(): Promise<{ name: string; available: boolean }[]> {
  if (!toolsCache) toolsCache = await detectTools();
  return Object.values(toolsCache).map((t) => ({ name: t.name, available: t.available }));
}

const PORT = 3003; // hardcoded — never read from an env var
const WORKERS = 8;
const HEARTBEAT_MS = 3000;
const MAX_BODY_BYTES = 1024 * 1024;
// Only real scan-plane endpoints. The former /oob, /firewall, /sharding and
// /monitoring endpoints were REMOVED — they served simulated (fake) data.
const API_PATHS = new Set(["/health", "/scans", "/start", "/kill"]);

const bootTime = Date.now();

// ── HTTP router ───────────────────────────────────────────────────────────────

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

async function handleApi(req: IncomingMessage, res: ServerResponse, engine: ScanEngine): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    });
    res.end();
    return;
  }

  if (req.method === "GET" && path === "/health") {
    sendJson(res, 200, {
      ok: true,
      activeScans: engine.activeCount(),
      workers: WORKERS,
      uptimeSec: Math.floor((Date.now() - bootTime) / 1000),
      lastKillLatencyMs: engine.lastKillLatencyMs,
      tools: await toolStatus(),
    });
    return;
  }

  if (req.method === "GET" && path === "/scans") {
    sendJson(res, 200, { scans: engine.listScans() });
    return;
  }

  if (req.method === "POST" && path === "/start") {
    let body: unknown;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      sendJson(res, 400, { ok: false, error: "invalid JSON body" });
      return;
    }
    const result = engine.start((body ?? {}) as Record<string, unknown>);
    if (result.ok) {
      sendJson(res, 200, result);
    } else {
      sendJson(res, result.error === "already running" ? 409 : 400, result);
    }
    return;
  }

  if (req.method === "POST" && path === "/kill") {
    let body: Record<string, unknown> = {};
    try {
      const raw = await readBody(req);
      body = raw.trim().length > 0 ? (JSON.parse(raw) as Record<string, unknown>) : {};
    } catch {
      sendJson(res, 400, { ok: false, error: "invalid JSON body" });
      return;
    }
    const scanId = typeof body.scanId === "string" && body.scanId.length > 0 ? body.scanId : undefined;
    sendJson(res, 200, engine.kill(scanId));
    return;
  }

  sendJson(res, 404, { ok: false, error: `no route: ${req.method} ${path}` });
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

const engine = new ScanEngine((event, payload) => io.emit(event, payload));

// NOTE: the OOB, firewall, sharding and monitoring SIMULATORS were removed —
// they broadcast fabricated (RNG) data. Only the real scan engine runs here.

const httpServer = createServer((req, res) => {
  handleApi(req, res, engine).catch((err: unknown) => {
    logError("unhandled route error", err);
    if (!res.headersSent) sendJson(res, 400, { ok: false, error: "bad request" });
  });
});

const io = new Server(httpServer, {
  // DO NOT change the path — the Caddy gateway forwards /?XTransformPort=3003.
  path: "/",
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingTimeout: 60000,
  pingInterval: 25000,
  serveClient: false,
});

// engine.io with path "/" intercepts EVERY http request; divert our API paths.
const engineAny = io.engine as unknown as {
  handleRequest: (req: IncomingMessage, res: ServerResponse) => void;
};
const originalHandleRequest = engineAny.handleRequest.bind(io.engine);
engineAny.handleRequest = (req: IncomingMessage, res: ServerResponse) => {
  const pathname = (req.url ?? "/").split("?")[0];
  if (API_PATHS.has(pathname)) {
    handleApi(req, res, engine).catch((err: unknown) => {
      logError("unhandled route error", err);
      if (!res.headersSent) sendJson(res, 400, { ok: false, error: "bad request" });
    });
    return;
  }
  originalHandleRequest(req, res);
};

io.on("connection", (socket) => {
  log(`bus client connected (${socket.id}) — ${io.engine.clientsCount} total`);
  socket.on("disconnect", (reason) => {
    log(`bus client disconnected (${socket.id}, ${reason}) — ${io.engine.clientsCount} total`);
  });
  socket.on("error", (err) => logError(`socket error (${socket.id})`, err));
});

// Heartbeat — engine:stats every 3s (requestsPerMin = rolling 60s count).
setInterval(() => {
  try {
    io.emit("engine:stats", {
      activeScans: engine.activeCount(),
      requestsPerMin: engine.requestsPerMin(),
      workers: WORKERS,
      uptimeSec: Math.floor((Date.now() - bootTime) / 1000),
      bus: "connected",
    });
  } catch (err) {
    logError("heartbeat failed", err);
  }
}, HEARTBEAT_MS);

httpServer.listen(PORT, () => {
  log(`scan-engine up on :${PORT} — bus path "/", API: GET /health, GET /scans, POST /start, POST /kill`);
});

// ── Robustness: never crash on a stray error ─────────────────────────────────

process.on("uncaughtException", (err) => logError("uncaughtException", err));
process.on("unhandledRejection", (err) => logError("unhandledRejection", err));

let shuttingDown = false;
const shutdown = (signal: string) => {
  if (shuttingDown) return; // guard against double-fire (hot reloads re-register handlers)
  shuttingDown = true;
  log(`received ${signal} — shutting down`);
  try {
    io.close();
  } catch {
    /* already closed */
  }
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
};
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// hot-reload nudge 2 (task 13-a)
