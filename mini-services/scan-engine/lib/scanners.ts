// ─── Native active vulnerability scanners (our own detection engine) ─────────
//
// Real DAST detection implemented in TypeScript — NOT a wrapper around nuclei.
// These run against the injection points the crawler discovered and confirm a
// class of vulnerability from the application's own responses.
//
// SAFETY: every probe here is NON-DESTRUCTIVE and detection-only.
//   • No data is created, modified, deleted, or exfiltrated.
//   • Payloads are oracles (error-triggers, reflection canaries, read-only file
//     paths, tautologies) — never working exploits, shells, or OAST exfil.
//   • Only GET/POST are issued; request budgets are capped and scope-guarded.
// This is standard authorized DAST against an operator-attested target.

import type { ProbeCtx, RawFinding, InjectionPoint, HttpResp } from "./probes";
import { httpRequest } from "./probes";

const MAX_POINTS_PER_SCAN = 24;

// Requester indirection — defaults to the real scope-guarded httpRequest.
// Overridable in tests (via _setRequester) so the detectors can run against a
// local mock without touching the scope wall. Production always uses the real
// scope-guarded path.
type Requester = typeof httpRequest;
let requester: Requester = httpRequest;
export function _setRequester(fn: Requester): void {
  requester = fn;
}
export function _resetRequester(): void {
  requester = httpRequest;
}

/** Issue one request with `param` set to `value` on the given point. */
async function sendWith(ctx: ProbeCtx, point: InjectionPoint, value: string): Promise<HttpResp | null> {
  if (point.method === "POST") {
    const body = `${encodeURIComponent(point.param)}=${encodeURIComponent(value)}`;
    return requester(ctx, point.url, { method: "POST", body, contentType: point.contentType });
  }
  let u: URL;
  try {
    u = new URL(point.url);
  } catch {
    return null;
  }
  u.searchParams.set(point.param, value);
  return requester(ctx, u.toString(), { method: "GET" });
}

/** Normalized similarity of two bodies by length ratio (0..1, 1 = identical length). */
function lenSimilarity(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  if (la === 0 && lb === 0) return 1;
  return 1 - Math.abs(la - lb) / Math.max(la, lb, 1);
}

function points(ctx: ProbeCtx): InjectionPoint[] {
  return ctx.shared.injectionPoints.slice(0, MAX_POINTS_PER_SCAN);
}

// ─── SQL injection (error-based + boolean-based) ─────────────────────────────

const SQL_ERRORS = [
  /you have an error in your sql syntax/i,
  /warning:\s+mysqli?/i,
  /unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i,
  /sqlite3?(::|_| )?(error|exception)|sqlite_error/i,
  /unterminated quoted string/i,
  /pg::(syntax|undefined)|postgresql.*error|org\.postgresql\.util\.psqlexception/i,
  /ora-\d{5}/i,
  /microsoft (ole db|sql server|jet database)|odbc.*driver|incorrect syntax near/i,
  /sqlstate\[\w+\]/i,
];

export const scanSqli = (): ((ctx: ProbeCtx) => Promise<RawFinding[]>) => async (ctx) => {
  const pts = points(ctx);
  if (pts.length === 0) {
    ctx.note("injection.sql: no parameters to test (crawler found no injection points)");
    return [];
  }
  const findings: RawFinding[] = [];
  for (const p of pts) {
    const baseline = await sendWith(ctx, p, p.sampleValue);
    if (!baseline) continue;
    const baselineErr = SQL_ERRORS.some((re) => re.test(baseline.body));

    // 1) error-based: break the quoting
    const err = await sendWith(ctx, p, `${p.sampleValue}'`);
    if (err && !baselineErr) {
      const sig = SQL_ERRORS.find((re) => re.test(err.body));
      if (sig) {
        const snippet = (err.body.match(sig)?.[0] ?? "").slice(0, 140);
        findings.push(sqliFinding(p, "error-based", snippet, 25));
        continue;
      }
    }

    // 2) boolean-based: tautology vs contradiction
    const t = await sendWith(ctx, p, `${p.sampleValue}' AND '1'='1`);
    const f = await sendWith(ctx, p, `${p.sampleValue}' AND '1'='2`);
    if (t && f) {
      const trueLikeBaseline = lenSimilarity(t.body, baseline.body) > 0.95 && t.status === baseline.status;
      const falseDiffers = lenSimilarity(f.body, t.body) < 0.9 || f.status !== t.status;
      if (trueLikeBaseline && falseDiffers) {
        findings.push(
          sqliFinding(
            p,
            "boolean-based blind",
            `1=1 len ${t.body.length} (≈baseline), 1=2 len ${f.body.length} (diverged)`,
            20
          )
        );
      }
    }
  }
  ctx.note(`injection.sql: tested ${pts.length} point(s) — ${findings.length} SQLi`);
  return findings;
};

function sqliFinding(p: InjectionPoint, technique: string, evidence: string, lr: number): RawFinding {
  return {
    title: `SQL injection (${technique}) in '${p.param}'`,
    severity: "critical",
    category: "injection",
    description: `Parameter '${p.param}' on ${p.method} ${new URL(p.url).pathname} is injectable (${technique}). Detected from the application's own response — no data was read or modified.`,
    endpoint: `${p.method} ${p.url}`,
    cve: null,
    pocScript: `# ${technique} — detection only, non-destructive\n# param '${p.param}' on ${p.method} ${new URL(p.url).pathname}`,
    evidence: [{ kind: "error_match", content: JSON.stringify({ param: p.param, technique, evidence }), lr }],
  };
}

// ─── Reflected XSS ───────────────────────────────────────────────────────────

export const scanXss = (): ((ctx: ProbeCtx) => Promise<RawFinding[]>) => async (ctx) => {
  const pts = points(ctx);
  if (pts.length === 0) {
    ctx.note("xss.reflected: no parameters to test");
    return [];
  }
  const findings: RawFinding[] = [];
  for (const p of pts) {
    const canary = `sw${Math.random().toString(36).slice(2, 8)}`;
    const marker = `"'><x${canary}>`;
    const resp = await sendWith(ctx, p, marker);
    if (!resp) continue;
    const ct = resp.headers["content-type"] ?? "";
    if (!/text\/html|application\/xhtml/i.test(ct)) continue;
    // reflected UNENCODED (the raw < > and tag survive) → executable context
    if (resp.body.includes(`<x${canary}>`)) {
      findings.push({
        title: `Reflected XSS in '${p.param}'`,
        severity: "high",
        category: "client",
        description: `Parameter '${p.param}' reflects unencoded HTML markup into a text/html response, so attacker-controlled script executes in a victim's browser. Detected with a harmless marker tag — no live payload was run.`,
        endpoint: `${p.method} ${p.url}`,
        cve: null,
        pocScript: `# reflected marker <x${canary}> returned unencoded in HTML`,
        evidence: [{ kind: "dom_taint", content: JSON.stringify({ param: p.param, marker: `<x${canary}>`, reflectedUnencoded: true }), lr: 20 }],
      });
    }
  }
  ctx.note(`xss.reflected: tested ${pts.length} point(s) — ${findings.length} reflected XSS`);
  return findings;
};

// ─── Path traversal / LFI ────────────────────────────────────────────────────

const TRAVERSAL_PAYLOADS = [
  "../../../../../../../../etc/passwd",
  "....//....//....//....//....//etc/passwd",
  "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
  "..\\..\\..\\..\\..\\..\\windows\\win.ini",
];
const TRAVERSAL_SIGNATURES = [/root:.*:0:0:/, /\[extensions\]/i, /\[fonts\]/i, /; for 16-bit app support/i, /daemon:.*:\/usr\/sbin/];

export const scanTraversal = (): ((ctx: ProbeCtx) => Promise<RawFinding[]>) => async (ctx) => {
  const pts = points(ctx);
  if (pts.length === 0) {
    ctx.note("fileops.lfi: no parameters to test");
    return [];
  }
  const findings: RawFinding[] = [];
  for (const p of pts) {
    for (const payload of TRAVERSAL_PAYLOADS) {
      const resp = await sendWith(ctx, p, payload);
      if (!resp) continue;
      const sig = TRAVERSAL_SIGNATURES.find((re) => re.test(resp.body));
      if (sig) {
        findings.push({
          title: `Path traversal / LFI in '${p.param}'`,
          severity: "high",
          category: "files",
          description: `Parameter '${p.param}' resolves a traversal payload to a system file (signature ${sig.source.slice(0, 30)} matched). Local files outside the web root are readable.`,
          endpoint: `${p.method} ${p.url}`,
          cve: null,
          pocScript: `# traversal payload returned a system-file signature — read-only detection`,
          evidence: [{ kind: "error_match", content: JSON.stringify({ param: p.param, payload: payload.slice(0, 40), signature: sig.source }), lr: 30 }],
        });
        break; // one finding per point
      }
    }
  }
  ctx.note(`fileops.lfi: tested ${pts.length} point(s) — ${findings.length} traversal`);
  return findings;
};

// ─── Open redirect ───────────────────────────────────────────────────────────

const REDIRECT_PARAM = /redirect|redir|url|next|return|returnto|dest|goto|continue|target|to|forward/i;

export const scanOpenRedirect = (): ((ctx: ProbeCtx) => Promise<RawFinding[]>) => async (ctx) => {
  const pts = points(ctx).filter((p) => REDIRECT_PARAM.test(p.param));
  if (pts.length === 0) return [];
  const findings: RawFinding[] = [];
  const canaryHost = "swarmscan-canary.example";
  for (const p of pts) {
    const resp = await sendWith(ctx, p, `https://${canaryHost}/`);
    if (!resp) continue;
    const loc = resp.headers["location"] ?? "";
    let redirected = false;
    try {
      if (loc && new URL(loc, p.url).hostname === canaryHost) redirected = true;
    } catch {
      /* ignore */
    }
    if (!redirected && new RegExp(`https?://${canaryHost}`).test(resp.body) && /<meta[^>]+http-equiv=["']?refresh/i.test(resp.body)) {
      redirected = true;
    }
    if (redirected) {
      findings.push({
        title: `Open redirect in '${p.param}'`,
        severity: "medium",
        category: "redirect",
        description: `Parameter '${p.param}' redirects to an attacker-supplied external host (${canaryHost}). Enables phishing and OAuth token theft via trusted-domain redirects.`,
        endpoint: `${p.method} ${p.url}`,
        cve: null,
        pocScript: `# ${p.param}=https://attacker.tld/ → Location/meta-refresh to attacker host`,
        evidence: [{ kind: "boolean_diff", content: JSON.stringify({ param: p.param, location: loc.slice(0, 120) }), lr: 8 }],
      });
    }
  }
  ctx.note(`redirect: tested ${pts.length} candidate param(s) — ${findings.length} open redirect`);
  return findings;
};

// ─── Sensitive-path exposure (read-only) ─────────────────────────────────────

const EXPOSURE_PATHS: { path: string; sig: RegExp; sev: RawFinding["severity"]; what: string }[] = [
  { path: "/.env", sig: /(^|\n)\s*[A-Z0-9_]+\s*=/, sev: "critical", what: "environment file (.env) with secrets" },
  { path: "/actuator/env", sig: /"(propertySources|activeProfiles)"/, sev: "high", what: "Spring Boot actuator env" },
  { path: "/actuator", sig: /"_links"\s*:/, sev: "medium", what: "Spring Boot actuator index" },
  { path: "/server-status", sig: /apache server status|<title>apache status/i, sev: "medium", what: "Apache mod_status" },
  { path: "/swagger.json", sig: /"swagger"\s*:|"openapi"\s*:/, sev: "low", what: "Swagger/OpenAPI spec" },
  { path: "/openapi.json", sig: /"openapi"\s*:/, sev: "low", what: "OpenAPI spec" },
  { path: "/api-docs", sig: /"swagger"\s*:|"openapi"\s*:/, sev: "low", what: "API docs spec" },
  { path: "/phpinfo.php", sig: /<title>phpinfo\(\)/i, sev: "high", what: "phpinfo() output" },
  { path: "/.DS_Store", sig: /Bud1|\x00\x00\x00\x01Bud1/, sev: "low", what: "macOS .DS_Store directory listing" },
];

export const scanExposure = (): ((ctx: ProbeCtx) => Promise<RawFinding[]>) => async (ctx) => {
  const findings: RawFinding[] = [];
  for (const e of EXPOSURE_PATHS) {
    const resp = await requester(ctx, e.path, { method: "GET" });
    if (!resp || resp.status !== 200) continue;
    if (!e.sig.test(resp.body)) continue;
    findings.push({
      title: `Exposed ${e.what}`,
      severity: e.sev,
      category: "disclosure",
      description: `${e.path} is served (HTTP 200) and matches the ${e.what} signature. Sensitive configuration/metadata is publicly readable.`,
      endpoint: `${ctx.url.replace(/\/$/, "")}${e.path}`,
      cve: null,
      pocScript: `curl -s ${ctx.url.replace(/\/$/, "")}${e.path}`,
      evidence: [{ kind: "error_match", content: JSON.stringify({ path: e.path, status: resp.status, matched: e.what }), lr: e.sev === "critical" || e.sev === "high" ? 30 : 6 }],
    });
  }
  ctx.note(`exposure: probed ${EXPOSURE_PATHS.length} sensitive path(s) — ${findings.length} exposed`);
  return findings;
};
