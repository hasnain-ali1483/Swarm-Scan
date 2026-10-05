// ─── Target scope classification & validation (control-plane) ────────────────
// Mirrors mini-services/scan-engine/lib/scope.ts. The engine is an independent
// project and cannot be imported, so the essential rules are copied here. The
// engine re-validates at scan time — this layer gives fast UI/API feedback and
// is the gate on registering a target.

import { isIP } from "node:net";

export type ScanScope = "internal" | "external";
export type TargetKind = "host" | "cidr" | "url";

export interface ScopeVerdict {
  ok: boolean;
  reason: string;
}

/** Extract a bare host from a URL / host[:port] / CIDR string. */
export function hostOf(raw: string): string {
  const t = raw.trim();
  if (t.includes("/") && isIP(t.split("/")[0]) !== 0) return t.split("/")[0]; // CIDR
  try {
    return new URL(/^[a-z]+:\/\//i.test(t) ? t : `https://${t}`).hostname;
  } catch {
    return t.replace(/^[a-z]+:\/\//i, "").split("/")[0].split(":")[0];
  }
}

export function kindOf(raw: string): TargetKind {
  const t = raw.trim();
  if (/^[a-z]+:\/\//i.test(t)) return "url";
  if (/\/\d{1,3}$/.test(t) && isIP(t.split("/")[0]) !== 0) return "cidr";
  return "host";
}

export function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "[::1]") return true;
  if (isIP(h) === 4 && h.startsWith("127.")) return true;
  return false;
}

export function isPrivateAddress(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  const v = isIP(h);
  if (v === 4) {
    const o = h.split(".").map(Number);
    if (o[0] === 10) return true;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] === 192 && o[1] === 168) return true;
    if (o[0] === 169 && o[1] === 254) return true;
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true;
    if (o[0] === 127) return true;
    return false;
  }
  if (v === 6) {
    if (h.startsWith("fc") || h.startsWith("fd")) return true;
    if (h.startsWith("fe80")) return true;
    if (h === "::1") return true;
    return false;
  }
  return /\.(internal|local|lan|corp|intranet|home\.arpa)$/.test(h);
}

/** Validate a registered target value against its engagement scope. */
export function validateTargetValue(value: string, scope: ScanScope): ScopeVerdict {
  const raw = value.trim();
  if (!raw) return { ok: false, reason: "target value is required" };
  const host = hostOf(raw);
  if (!host) return { ok: false, reason: "could not parse a host from the target" };
  if (isLoopback(host)) {
    return { ok: false, reason: "localhost / loopback is not a valid scan target" };
  }
  const priv = isPrivateAddress(host);
  if (scope === "external" && priv) {
    return { ok: false, reason: `${host} is a private/internal address — register it under Internal scope` };
  }
  if (scope === "internal" && isIP(host) !== 0 && !priv) {
    return { ok: false, reason: `${host} is a public address — register it under External scope` };
  }
  return { ok: true, reason: "in scope" };
}
