"use client";

// ─── Shared scan status / policy / profile / severity-dots chips ─────────────

import {
  CheckCircle2,
  Clock,
  Loader2,
  ShieldCheck,
  TriangleAlert,
  Workflow,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import {
  SEVERITY_ORDER,
  type PolicyTier,
  type ScanProfile,
  type ScanStatus,
} from "@/lib/swarm/types";

export const SCAN_STATUS_META: Record<
  ScanStatus,
  { label: string; icon: LucideIcon; className: string; spin?: boolean; pulse?: boolean }
> = {
  queued: {
    label: "Queued",
    icon: Clock,
    className: "border-zinc-500/40 bg-zinc-500/10 text-zinc-400",
  },
  planning: {
    label: "Planning",
    icon: Workflow,
    className: "border-zinc-500/40 bg-zinc-500/10 text-zinc-400",
  },
  running: {
    label: "Running",
    icon: Loader2,
    className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
    spin: true,
    pulse: true,
  },
  verifying: {
    label: "Verifying",
    icon: ShieldCheck,
    className: "border-amber-500/40 bg-amber-500/10 text-amber-400",
    spin: true,
  },
  completed: {
    label: "Completed",
    icon: CheckCircle2,
    className: "border-emerald-500/25 bg-emerald-500/5 text-emerald-300/80",
  },
  killed: {
    label: "Killed",
    icon: XCircle,
    className: "border-red-500/40 bg-red-500/10 text-red-400",
  },
  failed: {
    label: "Failed",
    icon: TriangleAlert,
    className: "border-red-500/40 bg-red-500/10 text-red-400",
  },
};

export function isScanActive(status?: ScanStatus | null): boolean {
  return (
    status === "queued" ||
    status === "planning" ||
    status === "running" ||
    status === "verifying"
  );
}

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const meta = SCAN_STATUS_META[status] ?? SCAN_STATUS_META.queued;
  const Icon = meta.icon;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1.5 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
        meta.className
      )}
    >
      {meta.pulse && (
        <span className="h-1 w-1 rounded-full bg-current swarm-pulse" aria-hidden />
      )}
      <Icon className={cn("h-3 w-3", meta.spin && "animate-spin")} aria-hidden />
      {meta.label}
      <span className="sr-only">status: {meta.label}</span>
    </span>
  );
}

export function ProfileChip({ profile }: { profile: ScanProfile }) {
  return (
    <span className="inline-flex shrink-0 items-center rounded border border-zinc-700 bg-zinc-800/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-zinc-400">
      {profile}
    </span>
  );
}

export const POLICY_TIER_META: Record<PolicyTier, { label: string; className: string }> = {
  safe: {
    label: "safe",
    className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  },
  standard: {
    label: "standard",
    className: "border-zinc-500/40 bg-zinc-500/10 text-zinc-400",
  },
  aggressive: {
    label: "aggressive",
    className: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  },
};

export function PolicyTierChip({ tier }: { tier: PolicyTier }) {
  const meta = POLICY_TIER_META[tier] ?? POLICY_TIER_META.standard;
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
        meta.className
      )}
    >
      {meta.label}
    </span>
  );
}

/** Compact severity mini-dots with counts (used in scan rows). */
export function SeverityDots({ counts }: { counts?: Record<string, number> }) {
  if (!counts) return <span className="text-muted-foreground">—</span>;
  const entries = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  if (entries.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex items-center gap-2" aria-label="Findings by severity">
      {entries.map((s) => (
        <span
          key={s}
          className="flex items-center gap-1"
          title={`${SEVERITY_STYLES[s].label}: ${counts[s]}`}
        >
          <span className={cn("h-1.5 w-1.5 rounded-full", SEVERITY_STYLES[s].dot)} aria-hidden />
          <span className="font-mono text-[11px] text-zinc-400">{counts[s]}</span>
          <span className="sr-only">{`${SEVERITY_STYLES[s].label}: ${counts[s]}`}</span>
        </span>
      ))}
    </span>
  );
}

/** Thin progress bar + percentage label. */
export function ProgressBar({
  value,
  active,
  className,
}: {
  value: number;
  active?: boolean;
  className?: string;
}) {
  const pct = Math.max(0, Math.min(100, value ?? 0));
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className={cn(
            "h-full rounded-full transition-all duration-500",
            active ? "bg-primary" : "bg-emerald-500/70"
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-9 shrink-0 text-right font-mono text-[11px] text-zinc-400">
        {Math.round(pct)}%
      </span>
    </div>
  );
}
