// ─── Real probe implementations ─────────────────────────────────────────────
//
// Each probe performs genuine, SAFE, read-only reconnaissance/verification and
// returns findings parsed from real observations. Nothing here is destructive:
// no data is written, deleted, sprayed or exfiltrated. Where an industry tool
// is present it is preferred; otherwise a built-in TS probe runs. Offensive
// techniques with no safe automated form (credential spraying, MFA fatigue,
// detection evasion) are intentionally NOT implemented — the engine surfaces
// them as "manual authorized testing required" instead of weaponising them.

import { connect as tlsConnect } from "node:tls";
import { Socket } from "node:net";
import { resolve4, resolve6, reverse } from "node:dns/promises";
import { createHash } from "node:crypto";
import type { EvidenceKind, Severity } from "./findings";
import type { ScanScope } from "./scope";
import { inScope } from "./scope";
import type { ToolName, ToolStatus } from "./tools";
import { run } from "./tools";

export interface RawEvidence {
  kind: EvidenceKind;
  content: string;
  lr: number; // likelihood ratio — how strongly this evidence confirms
}

export interface RawFinding {
  title: string;
  severity: Severity;
  category: string;
  description: string;
  endpoint: string | null;
  cve: string | null;
  pocScript: string | null;
  evidence: RawEvidence[];
}

export interface ProbeCtx {
  host: string;
  url: string;
  scope: ScanScope;
  /** lab (owned/sandbox) vs external (real; detection-only). */
  environment: "lab" | "external";
  /** true only when active proof-of-exploit is permitted (aggressive tier AND lab target). */
  activeExploit: boolean;
  tools: Record<ToolName, ToolStatus>;
  /** report n requests spent (for live request counter). */
  onRequest: (n: number) => void;
  /** emit a live engine event from inside a probe. */
  note: (message: string) => void;
  /** shared discovery between probes within one scan. */
  shared: ScanShared;
}

/** A discovered place where attacker-controlled input enters the app. */
export interface InjectionPoint {
  url: string; // absolute URL (for GET, includes the query with the target param)
  method: "GET" | "POST";
  param: string; // the parameter name under test
  sampleValue: string; // the original/benign value observed
  contentType?: string; // for POST bodies
}

/** Cross-probe discovery passed down the DAG (recon → … → correlator). */
export interface ScanShared {
  addresses: string[];
  openPorts: number[];
  routes: string[];
  jsUrls: string[];
  tech: string[];
  injectionPoints: InjectionPoint[];
  /** matches from the single per-scan nuclei run, claimed by agents via tags. */
  nucleiFindings: NucleiHit[];
  nucleiConsumed: Set<string>;
}

export type Probe = (ctx: ProbeCtx) => Promise<RawFinding[]>;

const UA = "SwarmScan/1.0 (+authorized-pentest)";
const HTTP_TIMEOUT = 8000;

export interface HttpResp {
  status: number;
  headers: Record<string, string>;
  body: string;
  url: string;
  ms: number; // wall-clock round-trip (for time-based oracles)
}

/**
 * Scope-guarded HTTP request (GET/POST). Returns null if out of scope or on
 * network error. Used by probes AND the native scanners (lib/scanners.ts).
 * Always read-only intent: no destructive methods are ever issued.
 */
export async function httpRequest(
  ctx: ProbeCtx,
  target: string,
  opts: { method?: "GET" | "POST"; body?: string; contentType?: string } = {}
): Promise<HttpResp | null> {
  let u: URL;
  try {
    u = new URL(target, ctx.url);
  } catch {
    return null;
  }
  const verdict = await inScope(u.hostname, ctx.scope);
  if (!verdict.ok) {
    ctx.note(`egress blocked → ${u.hostname}: ${verdict.reason}`);
    return null;
  }
  ctx.onRequest(1);
  const t0 = Date.now();
  try {
    const headers: Record<string, string> = { "User-Agent": UA, Accept: "*/*" };
    if (opts.method === "POST") headers["Content-Type"] = opts.contentType ?? "application/x-www-form-urlencoded";
    const res = await fetch(u.toString(), {
      method: opts.method ?? "GET",
      headers,
      body: opts.method === "POST" ? opts.body ?? "" : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(HTTP_TIMEOUT),
    });
    const resHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => (resHeaders[k] = v));
    const buf = await res.text().catch(() => "");
    return { status: res.status, headers: resHeaders, body: buf.slice(0, 512 * 1024), url: u.toString(), ms: Date.now() - t0 };
  } catch {
    return null;
  }
}

/** Scope-guarded HTTP GET (convenience wrapper over httpRequest). */
async function httpGet(ctx: ProbeCtx, target: string): Promise<HttpResp | null> {
  return httpRequest(ctx, target, { method: "GET" });
}

// ─── recon: DNS asset enumeration ────────────────────────────────────────────

export const probeRecon: Probe = async (ctx) => {
  const findings: RawFinding[] = [];
  const addrs: string[] = [];
  ctx.onRequest(2);
  try {
    addrs.push(...(await resolve4(ctx.host)));
  } catch {
    /* no A */
  }
  try {
    addrs.push(...(await resolve6(ctx.host)));
  } catch {
    /* no AAAA */
  }
  ctx.shared.addresses = addrs;
  if (addrs.length === 0) {
    ctx.note(`recon: ${ctx.host} did not resolve (A/AAAA)`);
    return findings;
  }
  let ptr = "";
  try {
    const r = await reverse(addrs[0]);
    ptr = r[0] ?? "";
  } catch {
    /* no PTR */
  }

  // subfinder (external scope only) — real passive subdomain discovery.
  let subs: string[] = [];
  if (ctx.scope === "external" && ctx.tools.subfinder.available) {
    const res = await run(ctx.tools.subfinder.path ?? "subfinder", ["-d", ctx.host, "-silent"], { timeoutMs: 45_000 });
    if (res.ok) subs = res.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 200);
    ctx.note(`recon: subfinder found ${subs.length} subdomain(s)`);
  }

  findings.push({
    title: `Resolved attack surface for ${ctx.host}`,
    severity: "info",
    category: "recon",
    description:
      `${ctx.host} resolves to ${addrs.length} address(es)${ptr ? ` (PTR ${ptr})` : ""}` +
      (subs.length ? `; ${subs.length} subdomain(s) discovered via subfinder` : ""),
    endpoint: null,
    cve: null,
    pocScript: null,
    evidence: [
      { kind: "version_map", content: JSON.stringify({ host: ctx.host, addresses: addrs, ptr, subdomains: subs.slice(0, 25) }), lr: 1 },
    ],
  });
  return findings;
};

// ─── ports: TCP connect scan (nmap if present, else built-in) ────────────────

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017];
const SENSITIVE: Record<number, [string, Severity]> = {
  23: ["Telnet", "high"],
  445: ["SMB", "high"],
  1433: ["MSSQL", "high"],
  1521: ["Oracle DB", "high"],
  2375: ["Docker API (unauth)", "critical"],
  3306: ["MySQL", "high"],
  3389: ["RDP", "high"],
  5432: ["PostgreSQL", "high"],
  5900: ["VNC", "high"],
  6379: ["Redis (often unauth)", "high"],
  9200: ["Elasticsearch (often unauth)", "high"],
  11211: ["Memcached", "medium"],
  27017: ["MongoDB (often unauth)", "high"],
};

function tcpOpen(host: string, port: number, timeoutMs = 2500): Promise<boolean> {
  return new Promise((resolve) => {
    const s = new Socket();
    let done = false;
    const finish = (open: boolean) => {
      if (done) return;
      done = true;
      s.destroy();
      resolve(open);
    };
    s.setTimeout(timeoutMs);
    s.once("connect", () => finish(true));
    s.once("timeout", () => finish(false));
    s.once("error", () => finish(false));
    s.connect(port, host);
  });
}

export const probePorts: Probe = async (ctx) => {
  const findings: RawFinding[] = [];
  const target = ctx.shared.addresses[0] ?? ctx.host;

  let open: number[] = [];
  if (ctx.tools.nmap.available) {
    const res = await run(ctx.tools.nmap.path ?? "nmap", ["-Pn", "-T4", "--open", "-p", COMMON_PORTS.join(","), "-oG", "-", target], { timeoutMs: 120_000 });
    if (res.ok || res.stdout) {
      const m = res.stdout.match(/Ports:\s*(.+)/);
      if (m) {
        for (const seg of m[1].split(",")) {
          const pm = seg.trim().match(/^(\d+)\/open/);
          if (pm) open.push(Number(pm[1]));
        }
      }
      ctx.note(`ports: nmap found ${open.length} open on ${target}`);
    }
  } else {
    ctx.note(`ports: nmap unavailable — built-in TCP connect scan of ${COMMON_PORTS.length} common ports`);
    const results = await Promise.all(COMMON_PORTS.map(async (p) => ((await tcpOpen(target, p)) ? p : -1)));
    open = results.filter((p) => p > 0);
    ctx.onRequest(COMMON_PORTS.length);
  }
  ctx.shared.openPorts = open;
  if (open.length === 0) return findings;

  for (const p of open) {
    const sens = SENSITIVE[p];
    if (!sens) continue;
    const [svc, sev] = sens;
    findings.push({
      title: `Exposed ${svc} on ${target}:${p}`,
      severity: sev,
      category: "exposure",
      description: `TCP port ${p} (${svc}) is reachable on ${target}. Exposed management/data-plane ports are a direct attack surface and frequently misconfigured for unauthenticated access.`,
      endpoint: `${target}:${p}`,
      cve: null,
      pocScript: `# verify reachability (read-only)\nnc -vz ${target} ${p}`,
      evidence: [{ kind: "version_map", content: JSON.stringify({ host: target, port: p, service: svc, state: "open" }), lr: 8 }],
    });
  }
  return findings;
};

// ─── fingerprint: HTTP tech + security headers ───────────────────────────────

const SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"];

export const probeFingerprint: Probe = async (ctx) => {
  const findings: RawFinding[] = [];
  const res = await httpGet(ctx, ctx.url);
  if (!res) {
    ctx.note(`fingerprint: ${ctx.url} unreachable`);
    return findings;
  }
  const server = res.headers["server"] ?? "";
  const powered = res.headers["x-powered-by"] ?? "";
  const tech = [server, powered].filter(Boolean);
  ctx.shared.tech = tech;

  if (tech.length) {
    findings.push({
      title: `Server fingerprint: ${tech.join(" / ")}`,
      severity: "info",
      category: "recon",
      description: `HTTP banner discloses server/runtime: ${tech.join(", ")}. Version disclosure narrows an attacker's exploit search to matching CVEs.`,
      endpoint: res.url,
      cve: null,
      pocScript: `curl -sI ${res.url}`,
      evidence: [{ kind: "version_map", content: JSON.stringify({ server, "x-powered-by": powered, status: res.status }), lr: 2 }],
    });
  }

  const missing = SEC_HEADERS.filter((h) => !(h in res.headers));
  if (missing.length >= 2) {
    findings.push({
      title: `Missing security headers (${missing.length})`,
      severity: "low",
      category: "hardening",
      description: `Response is missing ${missing.join(", ")}. These headers mitigate clickjacking, MIME-sniffing and transport downgrade; their absence is a hardening gap.`,
      endpoint: res.url,
      cve: null,
      pocScript: `curl -sI ${res.url} | grep -iE "${SEC_HEADERS.join("|")}"`,
      evidence: [{ kind: "boolean_diff", content: JSON.stringify({ present: SEC_HEADERS.filter((h) => h in res.headers), missing }), lr: 2 }],
    });
  }
  return findings;
};

// ─── crypto: TLS inspection ──────────────────────────────────────────────────

export const probeTls: Probe = async (ctx) => {
  if (ctx.url.startsWith("http://")) {
    ctx.note("crypto: target is plain HTTP — no TLS to inspect");
    return [];
  }
  const port = Number(new URL(ctx.url).port || 443);
  ctx.onRequest(1);
  const info = await new Promise<{
    proto: string | null;
    cipher: string;
    daysLeft: number | null;
    issuer: string;
  } | null>((resolve) => {
    const s = tlsConnect(
      { host: ctx.host, port, servername: ctx.host, rejectUnauthorized: false, timeout: HTTP_TIMEOUT },
      () => {
        const cert = s.getPeerCertificate();
        const cipher = s.getCipher();
        let daysLeft: number | null = null;
        if (cert && cert.valid_to) {
          daysLeft = Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
        }
        resolve({
          proto: s.getProtocol(),
          cipher: cipher?.name ?? "",
          daysLeft,
          issuer: String(cert?.issuer?.O ?? cert?.issuer?.CN ?? ""),
        });
        s.end();
      }
    );
    s.once("error", () => resolve(null));
    s.once("timeout", () => {
      s.destroy();
      resolve(null);
    });
  });
  if (!info) {
    ctx.note(`crypto: TLS handshake to ${ctx.host}:${port} failed`);
    return [];
  }
  const findings: RawFinding[] = [];
  const weakProto = info.proto && /TLSv1(\.0|\.1)?$/.test(info.proto) && info.proto !== "TLSv1.2" && info.proto !== "TLSv1.3";
  if (weakProto) {
    findings.push({
      title: `Weak TLS protocol negotiated (${info.proto})`,
      severity: "medium",
      category: "crypto",
      description: `The server negotiated ${info.proto}, a deprecated protocol vulnerable to downgrade and known cipher attacks.`,
      endpoint: `${ctx.host}:${port}`,
      cve: null,
      pocScript: `openssl s_client -connect ${ctx.host}:${port} -tls1_1`,
      evidence: [{ kind: "version_map", content: JSON.stringify(info), lr: 6 }],
    });
  }
  if (info.daysLeft !== null && info.daysLeft < 0) {
    findings.push({
      title: `Expired TLS certificate (${Math.abs(info.daysLeft)}d ago)`,
      severity: "high",
      category: "crypto",
      description: `The certificate for ${ctx.host} expired ${Math.abs(info.daysLeft)} days ago (issuer ${info.issuer || "unknown"}). Clients either fail closed or users are trained to click through warnings — a MITM enabler.`,
      endpoint: `${ctx.host}:${port}`,
      cve: null,
      pocScript: `echo | openssl s_client -connect ${ctx.host}:${port} 2>/dev/null | openssl x509 -noout -dates`,
      evidence: [{ kind: "version_map", content: JSON.stringify(info), lr: 10 }],
    });
  } else if (info.daysLeft !== null && info.daysLeft < 14) {
    findings.push({
      title: `TLS certificate expiring soon (${info.daysLeft}d)`,
      severity: "low",
      category: "crypto",
      description: `Certificate for ${ctx.host} expires in ${info.daysLeft} days.`,
      endpoint: `${ctx.host}:${port}`,
      cve: null,
      pocScript: null,
      evidence: [{ kind: "version_map", content: JSON.stringify(info), lr: 1 }],
    });
  }
  ctx.note(`crypto: ${info.proto} ${info.cipher}${info.daysLeft !== null ? `, cert ${info.daysLeft}d` : ""}`);
  return findings;
};

// ─── crawler: route + asset discovery ────────────────────────────────────────

const MAX_INJECTION_POINTS = 60;

function addInjectionPoint(points: Map<string, InjectionPoint>, p: InjectionPoint): void {
  if (points.size >= MAX_INJECTION_POINTS) return;
  const key = `${p.method} ${new URL(p.url).pathname} ${p.param}`;
  if (!points.has(key)) points.set(key, p);
}

export const probeCrawl: Probe = async (ctx) => {
  const res = await httpGet(ctx, ctx.url);
  if (!res) return [];
  const links = new Set<string>();
  const js = new Set<string>();
  const points = new Map<string, InjectionPoint>();

  // Seed from the target URL's own query parameters.
  try {
    const base = new URL(ctx.url);
    for (const [k, v] of base.searchParams.entries()) {
      addInjectionPoint(points, { url: base.toString(), method: "GET", param: k, sampleValue: v });
    }
  } catch {
    /* ignore */
  }

  // href/src/action links — capture parameterized GET injection points.
  for (const m of res.body.matchAll(/(?:href|src|action)\s*=\s*["']([^"'#]+)["']/gi)) {
    const raw = m[1];
    if (/^(mailto:|tel:|javascript:|data:)/i.test(raw)) continue;
    try {
      const abs = new URL(raw, res.url);
      if (abs.hostname !== ctx.host) continue;
      links.add(abs.pathname);
      if (abs.pathname.endsWith(".js")) js.add(abs.toString());
      for (const [k, v] of abs.searchParams.entries()) {
        addInjectionPoint(points, { url: abs.toString(), method: "GET", param: k, sampleValue: v });
      }
    } catch {
      /* skip */
    }
  }

  // Forms — action + method + input/textarea/select field names.
  const formBlocks = res.body.match(/<form\b[\s\S]*?<\/form>/gi) ?? [];
  for (const form of formBlocks) {
    const actionM = form.match(/action\s*=\s*["']([^"']*)["']/i);
    const methodM = form.match(/method\s*=\s*["']([^"']*)["']/i);
    const method = (methodM?.[1] ?? "GET").toUpperCase() === "POST" ? "POST" : "GET";
    let actionUrl: URL;
    try {
      actionUrl = new URL(actionM?.[1] || res.url, res.url);
    } catch {
      continue;
    }
    if (actionUrl.hostname !== ctx.host) continue;
    const fields = new Set<string>();
    for (const fm of form.matchAll(/<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)) {
      fields.add(fm[1]);
    }
    for (const field of fields) {
      if (method === "POST") {
        addInjectionPoint(points, { url: actionUrl.toString(), method: "POST", param: field, sampleValue: "test", contentType: "application/x-www-form-urlencoded" });
      } else {
        const u = new URL(actionUrl.toString());
        u.searchParams.set(field, "test");
        addInjectionPoint(points, { url: u.toString(), method: "GET", param: field, sampleValue: "test" });
      }
    }
  }

  ctx.shared.routes = [...links].slice(0, 200);
  ctx.shared.jsUrls = [...js].slice(0, 50);
  ctx.shared.injectionPoints = [...points.values()];
  const forms = formBlocks.length;
  ctx.note(`crawler: ${links.size} route(s), ${js.size} script(s), ${forms} form(s), ${points.size} injection point(s)`);

  if (links.size === 0 && forms === 0) return [];
  return [
    {
      title: `Mapped ${links.size} route(s), ${forms} form(s), ${points.size} injection point(s)`,
      severity: "info",
      category: "discovery",
      description: `Crawl of ${res.url} enumerated ${links.size} same-origin routes, ${js.size} scripts, ${forms} forms and ${points.size} parameter injection points — the input surface the native scanners probe.`,
      endpoint: res.url,
      cve: null,
      pocScript: null,
      evidence: [{ kind: "version_map", content: JSON.stringify({ routes: [...links].slice(0, 30), forms, injectionPoints: points.size }), lr: 1 }],
    },
  ];
};

// ─── API / JS-aware discovery ────────────────────────────────────────────────
// SPAs hide their real input surface in JS bundles and OpenAPI specs rather
// than static HTML. This probe mines both so the native scanners get real
// endpoints + parameters to test on single-page / API-first apps.

/** Dedup-and-cap append into the shared injection-point set. */
function pushPoint(shared: ScanShared, p: InjectionPoint): void {
  if (shared.injectionPoints.length >= MAX_INJECTION_POINTS) return;
  let path: string;
  try {
    path = new URL(p.url).pathname;
  } catch {
    return;
  }
  const key = `${p.method} ${path} ${p.param}`;
  const exists = shared.injectionPoints.some((e) => {
    try {
      return `${e.method} ${new URL(e.url).pathname} ${e.param}` === key;
    } catch {
      return false;
    }
  });
  if (!exists) shared.injectionPoints.push(p);
}

// Endpoint-ish string literals and client call sites inside JS/inline scripts.
const JS_PATH_RE = /['"`](\/(?:api|rest|graphql|v\d+|services|public|auth|users?|products?|search|admin|account|orders?|cart|login|upload|files?|download)[A-Za-z0-9_\-/.]*(?:\?[^'"`\s]*)?)['"`]/gi;
const JS_CALL_RE = /\.(?:get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]/gi;
const JS_FETCH_RE = /(?:fetch|axios)\(\s*['"`]([^'"`]+)['"`]/gi;

function harvestEndpoints(text: string): string[] {
  const out = new Set<string>();
  for (const re of [JS_PATH_RE, JS_CALL_RE, JS_FETCH_RE]) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const raw = m[1];
      if (!raw || raw.length > 300) continue;
      if (/\.(png|jpe?g|gif|svg|woff2?|ttf|css|map|ico)(\?|$)/i.test(raw)) continue;
      if (raw.startsWith("/") || raw.startsWith("http")) out.add(raw);
    }
  }
  return [...out];
}

function addEndpoint(ctx: ProbeCtx, routes: Set<string>, raw: string): void {
  let abs: URL;
  try {
    abs = new URL(raw, ctx.url);
  } catch {
    return;
  }
  if (abs.hostname !== ctx.host) return;
  routes.add(abs.pathname);
  for (const [k, v] of abs.searchParams.entries()) {
    pushPoint(ctx.shared, { url: abs.toString(), method: "GET", param: k, sampleValue: v || "1" });
  }
}

const SWAGGER_LOCATIONS = [
  "/swagger.json",
  "/openapi.json",
  "/api-docs",
  "/api-docs.json",
  "/v2/api-docs",
  "/v3/api-docs",
  "/swagger/v1/swagger.json",
  "/api/swagger.json",
  "/api/openapi.json",
  "/api/v1/openapi.json",
];

interface OpenApiParam {
  name?: string;
  in?: string;
}
interface OpenApiSpec {
  paths?: Record<string, Record<string, { parameters?: OpenApiParam[]; requestBody?: { content?: Record<string, { schema?: { properties?: Record<string, unknown> } }> } }>>;
  basePath?: string;
}

/** Turn a parsed OpenAPI/Swagger spec into injection points. Returns count. */
function pointsFromSpec(ctx: ProbeCtx, spec: OpenApiSpec, routes: Set<string>): number {
  let n = 0;
  const base = typeof spec.basePath === "string" ? spec.basePath.replace(/\/$/, "") : "";
  const paths = spec.paths ?? {};
  for (const [rawPath, methods] of Object.entries(paths)) {
    if (!methods || typeof methods !== "object") continue;
    // substitute {id}-style path params with a benign sample so the URL resolves
    const concretePath = base + rawPath.replace(/\{[^}]+\}/g, "1");
    let abs: URL;
    try {
      abs = new URL(concretePath, ctx.url);
    } catch {
      continue;
    }
    if (abs.hostname !== ctx.host) continue;
    routes.add(abs.pathname);
    for (const [method, op] of Object.entries(methods)) {
      const m = method.toUpperCase();
      if (m !== "GET" && m !== "POST") continue;
      for (const pr of op.parameters ?? []) {
        if (!pr.name) continue;
        if (pr.in === "query") {
          const u = new URL(abs.toString());
          u.searchParams.set(pr.name, "1");
          pushPoint(ctx.shared, { url: u.toString(), method: "GET", param: pr.name, sampleValue: "1" });
          n++;
        } else if ((pr.in === "formData" || pr.in === "body") && m === "POST") {
          pushPoint(ctx.shared, { url: abs.toString(), method: "POST", param: pr.name, sampleValue: "1", contentType: "application/x-www-form-urlencoded" });
          n++;
        }
      }
      // OpenAPI 3 requestBody → body field names
      const content = op.requestBody?.content ?? {};
      for (const media of Object.values(content)) {
        const props = media?.schema?.properties ?? {};
        for (const field of Object.keys(props)) {
          pushPoint(ctx.shared, { url: abs.toString(), method: "POST", param: field, sampleValue: "1", contentType: "application/json" });
          n++;
        }
      }
    }
  }
  return n;
}

export const probeApiDiscovery: Probe = async (ctx) => {
  const before = ctx.shared.injectionPoints.length;
  const routes = new Set<string>(ctx.shared.routes);

  // 1) Inline scripts + raw HTML of the root.
  const root = await httpGet(ctx, ctx.url);
  if (root) {
    for (const ep of harvestEndpoints(root.body)) addEndpoint(ctx, routes, ep);
  }

  // 2) JS bundles discovered by the crawler.
  let jsScanned = 0;
  for (const u of ctx.shared.jsUrls.slice(0, 12)) {
    const res = await httpGet(ctx, u);
    if (!res) continue;
    jsScanned++;
    for (const ep of harvestEndpoints(res.body)) addEndpoint(ctx, routes, ep);
  }

  // 3) OpenAPI / Swagger specs.
  let specParams = 0;
  let specFound: string | null = null;
  for (const loc of SWAGGER_LOCATIONS) {
    const res = await httpGet(ctx, loc);
    if (!res || res.status !== 200) continue;
    let spec: OpenApiSpec;
    try {
      spec = JSON.parse(res.body) as OpenApiSpec;
    } catch {
      continue;
    }
    if (!spec || typeof spec !== "object" || !spec.paths) continue;
    specFound = loc;
    specParams += pointsFromSpec(ctx, spec, routes);
    break; // first valid spec wins
  }

  ctx.shared.routes = [...routes].slice(0, 400);
  const added = ctx.shared.injectionPoints.length - before;
  ctx.note(
    `api-discovery: scanned ${jsScanned} JS bundle(s)${specFound ? `, parsed spec ${specFound}` : ", no spec"} — +${added} injection point(s)`
  );

  if (added === 0 && !specFound) return [];
  return [
    {
      title: `API surface discovered — ${added} parameter(s)${specFound ? ` from ${specFound}` : " from JS"}`,
      severity: specFound ? "low" : "info",
      category: "discovery",
      description:
        `JS/API-aware crawl recovered ${added} injectable parameter(s) across ${routes.size} route(s)` +
        (specFound ? `; an OpenAPI/Swagger spec is publicly served at ${specFound} (exposes the full API contract to attackers).` : " by mining client-side bundles.") +
        " These feed the native injection/XSS/traversal scanners on SPA & API-first targets.",
      endpoint: specFound ? `${ctx.url.replace(/\/$/, "")}${specFound}` : ctx.url,
      cve: null,
      pocScript: null,
      evidence: [{ kind: "version_map", content: JSON.stringify({ jsScanned, spec: specFound, addedParams: added, specParams, totalRoutes: routes.size }), lr: specFound ? 3 : 1 }],
    },
  ];
};

// ─── gitrepo: exposed .git ───────────────────────────────────────────────────

export const probeGit: Probe = async (ctx) => {
  const head = await httpGet(ctx, "/.git/HEAD");
  if (!head || head.status !== 200 || !/^ref:\s/m.test(head.body)) return [];
  const cfg = await httpGet(ctx, "/.git/config");
  const hasRemote = !!cfg && /\[remote /.test(cfg.body);
  ctx.note("gitrepo: exposed .git directory detected");
  return [
    {
      title: "Exposed .git repository",
      severity: "high",
      category: "disclosure",
      description: `/.git/HEAD is served (HTTP 200, contains a ref). The repository — including full source history and any secret ever committed — can be reconstructed with git-dumper.${hasRemote ? " .git/config exposes a remote URL." : ""}`,
      endpoint: `${ctx.url}/.git/`,
      cve: null,
      pocScript: `git-dumper ${ctx.url}/.git/ ./loot   # read-only reconstruction`,
      evidence: [
        { kind: "error_match", content: JSON.stringify({ path: "/.git/HEAD", status: head.status, head: head.body.trim().slice(0, 80) }), lr: 40 },
      ],
    },
  ];
};

// ─── secrets: key patterns in served JS ──────────────────────────────────────

const SECRET_PATTERNS: [string, RegExp][] = [
  ["AWS Access Key", /AKIA[0-9A-Z]{16}/],
  ["Google API Key", /AIza[0-9A-Za-z_-]{35}/],
  ["Slack Token", /xox[baprs]-[0-9A-Za-z-]{10,}/],
  ["Stripe Live Key", /sk_live_[0-9A-Za-z]{24,}/],
  ["Private Key Block", /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/],
  ["Generic Bearer", /bearer\s+[A-Za-z0-9._-]{20,}/i],
];

export const probeSecrets: Probe = async (ctx) => {
  const urls = ctx.shared.jsUrls.slice(0, 20);
  if (urls.length === 0) {
    ctx.note("secrets: no JS assets discovered to scan");
    return [];
  }
  const hits: { file: string; type: string; sample: string }[] = [];
  for (const u of urls) {
    const res = await httpGet(ctx, u);
    if (!res) continue;
    for (const [type, re] of SECRET_PATTERNS) {
      const m = res.body.match(re);
      if (m) {
        const redacted = m[0].slice(0, 6) + "…" + createHash("sha256").update(m[0]).digest("hex").slice(0, 8);
        hits.push({ file: u, type, sample: redacted });
      }
    }
  }
  if (hits.length === 0) return [];
  ctx.note(`secrets: ${hits.length} candidate secret(s) in JS bundles`);
  return [
    {
      title: `${hits.length} secret(s) leaked in client JS`,
      severity: "high",
      category: "secrets",
      description: `Static JS bundles contain ${hits.length} high-entropy credential pattern(s) (${[...new Set(hits.map((h) => h.type))].join(", ")}). Client-shipped keys are trivially harvested; a staging key often works against production.`,
      endpoint: hits[0].file,
      cve: null,
      pocScript: `# keys are hash-redacted in evidence; rotate immediately`,
      evidence: hits.slice(0, 10).map((h) => ({ kind: "error_match" as EvidenceKind, content: JSON.stringify(h), lr: 15 })),
    },
  ];
};

// ─── nuclei: template-based vulnerability detection ──────────────────────────
//
// Efficient integration: nuclei is run ONCE per scan (loading the ~10k-template
// corpus is expensive), and the parsed matches are distributed to the agents by
// tag. The first nuclei agent triggers the single run; the rest read the shared
// cache and claim the matches whose tags intersect theirs (deduped).

const NUCLEI_SEV: Record<string, Severity> = {
  info: "info",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
  unknown: "info",
};

/** Union of every agent's tag set — the single run requests all of them at once. */
const ALL_NUCLEI_TAGS = [
  "ssrf", "redirect", "sqli", "injection", "xss", "lfi", "traversal",
  "deserialization", "default-login", "auth-bypass", "exposure",
  "graphql", "swagger", "api", "aws", "cloud", "cve", "misconfig",
];

export interface NucleiHit {
  key: string; // dedup key
  tags: string[];
  severity: Severity;
  name: string;
  templateId: string;
  matchedAt: string;
  cve: string | null;
  description: string;
  curl: string | null;
}

// Per-scan single-run guard (keyed by the scan's shared object).
const nucleiRuns = new WeakMap<ScanShared, Promise<void>>();

async function ensureNucleiRun(ctx: ProbeCtx): Promise<void> {
  const existing = nucleiRuns.get(ctx.shared);
  if (existing) return existing;
  const p = (async () => {
    const args = [
      "-u", ctx.url, "-jsonl", "-silent", "-no-color", "-disable-update-check",
      "-timeout", "10", "-rate-limit", "150", "-tags", ALL_NUCLEI_TAGS.join(","),
    ];
    ctx.note(`nuclei: single-pass template scan started (${ALL_NUCLEI_TAGS.length} tag classes)`);
    const res = await run(ctx.tools.nuclei.path ?? "nuclei", args, { timeoutMs: 300_000 });
    ctx.onRequest(20);
    for (const line of res.stdout.split(/\r?\n/)) {
      if (!line.trim()) continue;
      let o: Record<string, unknown>;
      try {
        o = JSON.parse(line);
      } catch {
        continue;
      }
      const info = (o.info ?? {}) as Record<string, unknown>;
      const sev = NUCLEI_SEV[String(info.severity ?? "unknown").toLowerCase()] ?? "info";
      const classification = (info.classification ?? {}) as Record<string, unknown>;
      const cveList = (classification["cve-id"] as string[] | undefined) ?? [];
      const templateId = String(o["template-id"] ?? "");
      const matchedAt = String(o["matched-at"] ?? ctx.url);
      ctx.shared.nucleiFindings.push({
        key: `${templateId}@${matchedAt}`,
        tags: ((info.tags as string[] | undefined) ?? []).map((t) => String(t).toLowerCase()),
        severity: sev,
        name: String(info.name ?? templateId ?? "nuclei match"),
        templateId,
        matchedAt,
        cve: cveList[0] ?? null,
        description: String(info.description ?? `nuclei template ${templateId} matched`).trim(),
        curl: o["curl-command"] ? String(o["curl-command"]) : null,
      });
    }
    ctx.note(`nuclei: single-pass complete — ${ctx.shared.nucleiFindings.length} total match(es)`);
  })();
  nucleiRuns.set(ctx.shared, p);
  return p;
}

/** An agent-scoped view over the shared nuclei results, claiming matches by tag. */
export function nucleiProbe(tags: string[], category: string): Probe {
  const want = tags.map((t) => t.toLowerCase());
  return async (ctx) => {
    if (!ctx.tools.nuclei.available) {
      ctx.note(`${category}: nuclei unavailable — install projectdiscovery/nuclei for template-based detection`);
      return [];
    }
    await ensureNucleiRun(ctx);
    const findings: RawFinding[] = [];
    for (const hit of ctx.shared.nucleiFindings) {
      if (ctx.shared.nucleiConsumed.has(hit.key)) continue;
      if (!hit.tags.some((t) => want.includes(t))) continue;
      ctx.shared.nucleiConsumed.add(hit.key);
      findings.push({
        title: hit.name,
        severity: hit.severity,
        category,
        description: hit.description || `nuclei template ${hit.templateId} matched at ${hit.matchedAt}`,
        endpoint: hit.matchedAt,
        cve: hit.cve,
        pocScript: hit.curl,
        evidence: [
          {
            kind: "error_match",
            content: JSON.stringify({ template: hit.templateId, matchedAt: hit.matchedAt, severity: hit.severity, tags: hit.tags }),
            lr: hit.severity === "critical" || hit.severity === "high" ? 30 : 8,
          },
        ],
      });
    }
    ctx.note(`${category}: claimed ${findings.length} nuclei match(es) [tags ${want.join(",")}]`);
    return findings;
  };
}
