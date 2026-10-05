"use client";

// ─── Shared formatting/color helpers for SwarmScan views ─────────────────────
// Owned by the orchestrator — subagents must NOT edit. Import freely.

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { ConfidenceBand, Severity } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_STYLES: Record<
  Severity,
  { badge: string; dot: string; text: string; bar: string; label: string }
> = {
  critical: {
    badge: "bg-red-500/15 text-red-400 border-red-500/40",
    dot: "bg-red-500",
    text: "text-red-400",
    bar: "bg-red-500",
    label: "Critical",
  },
  high: {
    badge: "bg-orange-500/15 text-orange-400 border-orange-500/40",
    dot: "bg-orange-500",
    text: "text-orange-400",
    bar: "bg-orange-500",
    label: "High",
  },
  medium: {
    badge: "bg-amber-500/15 text-amber-400 border-amber-500/40",
    dot: "bg-amber-500",
    text: "text-amber-400",
    bar: "bg-amber-500",
    label: "Medium",
  },
  low: {
    badge: "bg-yellow-500/12 text-yellow-500 border-yellow-500/35",
    dot: "bg-yellow-500",
    text: "text-yellow-500",
    bar: "bg-yellow-500",
    label: "Low",
  },
  info: {
    badge: "bg-zinc-500/15 text-zinc-400 border-zinc-500/40",
    dot: "bg-zinc-400",
    text: "text-zinc-400",
    bar: "bg-zinc-400",
    label: "Info",
  },
};

export const BAND_STYLES: Record<
  ConfidenceBand,
  { badge: string; text: string; label: string; hint: string }
> = {
  suspected: {
    badge: "bg-zinc-500/15 text-zinc-300 border-zinc-500/40",
    text: "text-zinc-300",
    label: "Suspected",
    hint: "0–59 · informational, single-technique signal",
  },
  likely: {
    badge: "bg-amber-500/15 text-amber-400 border-amber-500/40",
    text: "text-amber-400",
    label: "Likely",
    hint: "60–84 · verify-required, two-technique confirmation",
  },
  confirmed: {
    badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
    text: "text-emerald-400",
    label: "Confirmed",
    hint: "85–99 · auto-verified, independent techniques agree",
  },
};

export const EVENT_TYPE_STYLES: Record<string, { text: string; label: string }> = {
  finding: { text: "text-red-400", label: "FINDING" },
  agent_state: { text: "text-zinc-400", label: "AGENT" },
  policy: { text: "text-amber-400", label: "POLICY" },
  kill: { text: "text-red-500 font-semibold", label: "KILL" },
  oob: { text: "text-emerald-400", label: "OOB" },
  chain: { text: "text-fuchsia-400", label: "CHAIN" },
  system: { text: "text-zinc-500", label: "SYSTEM" },
  revisit: { text: "text-teal-400", label: "REVISIT" },
  integration: { text: "text-teal-400", label: "INTEGRATION" },
};

export function formatHash(hash: string, head = 10, tail = 6): string {
  if (!hash) return "";
  if (hash.length <= head + tail + 1) return hash;
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`;
}

export function timeAgo(iso: string | Date): string {
  const t = typeof iso === "string" ? new Date(iso).getTime() : iso.getTime();
  const diff = Math.max(0, Date.now() - t);
  const s = Math.floor(diff / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(t).toLocaleDateString();
}

export function formatDuration(startedAt?: string | null, endedAt?: string | null): string {
  if (!startedAt) return "—";
  const start = new Date(startedAt).getTime();
  const end = endedAt ? new Date(endedAt).getTime() : Date.now();
  const s = Math.max(0, Math.round((end - start) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}m ${rs}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

export function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}

export function truncateMiddle(s: string, max = 42): string {
  if (s.length <= max) return s;
  const half = Math.floor((max - 1) / 2);
  return `${s.slice(0, half)}…${s.slice(-half)}`;
}
