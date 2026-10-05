// ─── Scope & authorization enforcement ──────────────────────────────────────
//
// The hard safety wall of the real engine. Before ANY probe touches the
// network, the target is validated here:
//   • localhost / loopback is ALWAYS rejected as a scan target
//   • an EXTERNAL engagement may only hit public addresses (RFC1918 / CGNAT /
//     link-local / ULA are rejected — you cannot "external pentest" a private
//     net)
//   • an INTERNAL engagement may only hit private addresses (a public address
//     in an internal engagement is out of scope)
//   • every probe host must resolve to the scan's locked scope — the egress
//     guard (inScope) is called on each outbound host so a crawler-discovered
//     off-scope link never generates traffic.
//
// Authorization is attested per target in the control plane; the engine
// refuses a scan whose target is not flagged authorized.

import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

export type ScanScope = "internal" | "external";

export interface ScopeTarget {
  /** raw operator input: URL or bare host/ip */
  raw: string;
  /** hostname or ip, no scheme/port/path */
  host: string;
  /** full URL to probe (scheme defaulted to https for external, http for internal) */
  url: string;
  scope: ScanScope;
}

export interface ScopeVerdict {
  ok: boolean;
  reason: string;
}

/** Extract a bare hostname/IP from a URL or host[:port] string. */
export function hostOf(raw: string): string {
  const t = raw.trim();
  try {
    return new URL(/^[a-z]+:\/\//i.test(t) ? t : `https://${t}`).hostname;
  } catch {
    return t.replace(/^[a-z]+:\/\//i, "").split("/")[0].split(":")[0];
  }
}

/** Loopback / localhost — never a valid scan target. */
export function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "[::1]") return true;
  if (isIP(h) === 4 && h.startsWith("127.")) return true;
  if (isIP(h) === 6 && (h === "::1" || h.replace(/^\[|\]$/g, "") === "::1")) return true;
  return false;
}

/** RFC1918 / CGNAT / link-local / ULA / metadata — "private/internal" space. */
export function isPrivateAddress(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  const v = isIP(h);
  if (v === 4) {
    const o = h.split(".").map(Number);
    if (o[0] === 10) return true; // 10/8
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true; // 172.16/12
    if (o[0] === 192 && o[1] === 168) return true; // 192.168/16
    if (o[0] === 169 && o[1] === 254) return true; // link-local + 169.254.169.254 metadata
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true; // CGNAT 100.64/10
    if (o[0] === 127) return true; // loopback counts as private
    return false;
  }
  if (v === 6) {
    if (h.startsWith("fc") || h.startsWith("fd")) return true; // ULA fc00::/7
    if (h.startsWith("fe80")) return true; // link-local
    if (h === "::1") return true;
    return false;
  }
  // A name (not an IP). ".internal"/".local"/".corp"/".lan" are internal hints.
  return /\.(internal|local|lan|corp|intranet|home\.arpa)$/.test(h);
}

/**
 * Validate a target against the engagement scope. Pure/synchronous checks on
 * the literal host; name→IP resolution is enforced separately at probe time by
 * inScope() against the resolved address.
 */
export function validateTarget(host: string, scope: ScanScope): ScopeVerdict {
  if (!host) return { ok: false, reason: "empty target host" };
  if (isLoopback(host)) {
    return { ok: false, reason: "localhost / loopback is not a valid scan target" };
  }
  const priv = isPrivateAddress(host);
  if (scope === "external" && priv) {
    return {
      ok: false,
      reason: `${host} is a private/internal address — not valid for an EXTERNAL engagement (use Internal scope)`,
    };
  }
  if (scope === "internal" && isIP(host) !== 0 && !priv) {
    return {
      ok: false,
      reason: `${host} is a public address — not valid for an INTERNAL engagement (use External scope)`,
    };
  }
  return { ok: true, reason: "in scope" };
}

/** Build the canonical probe URL + host for an accepted target. */
export function resolveScopeTarget(raw: string, scope: ScanScope): ScopeTarget {
  const host = hostOf(raw);
  const t = raw.trim();
  const hasScheme = /^[a-z]+:\/\//i.test(t);
  const scheme = scope === "internal" ? "http" : "https";
  const url = hasScheme ? t : `${scheme}://${host}`;
  return { raw: t, host, url, scope };
}

/**
 * Egress guard — called before every outbound host. A probe may only reach a
 * host whose RESOLVED address matches the engagement scope and is not loopback.
 * This is what stops a crawler-discovered third-party link from being scanned.
 */
export async function inScope(host: string, scope: ScanScope): Promise<ScopeVerdict> {
  if (isLoopback(host)) return { ok: false, reason: "loopback blocked" };
  let addr = host;
  if (isIP(host) === 0) {
    try {
      const res = await lookup(host);
      addr = res.address;
    } catch {
      return { ok: false, reason: `DNS resolution failed for ${host}` };
    }
  }
  if (isLoopback(addr)) return { ok: false, reason: `${host} resolves to loopback — blocked` };
  const priv = isPrivateAddress(addr);
  if (scope === "external" && priv) {
    return { ok: false, reason: `${host} resolves to private ${addr} — out of external scope` };
  }
  if (scope === "internal" && !priv) {
    return { ok: false, reason: `${host} resolves to public ${addr} — out of internal scope` };
  }
  return { ok: true, reason: `in scope (${addr})` };
}
