"use client";

// ─── Destructive payload registry — static policy matrix from the spec ────────

import { Check, ShieldAlert, X } from "lucide-react";
import { cn } from "@/lib/swarm/format";

type Verdict = "denied" | "approval" | "permitted";

interface PayloadClass {
  name: string;
  verdict: Verdict;
}

const PAYLOAD_CLASSES: PayloadClass[] = [
  { name: "DELETE / UPDATE queries", verdict: "denied" },
  { name: "File writes outside /tmp", verdict: "denied" },
  { name: "State-changing GraphQL mutations", verdict: "denied" },
  { name: "Data exfiltration > 1 KB", verdict: "approval" },
  { name: "SELECT-only PoC", verdict: "permitted" },
];

const VERDICT_META: Record<
  Verdict,
  { icon: typeof X; label: string; chip: string }
> = {
  denied: {
    icon: X,
    label: "denied",
    chip: "bg-red-500/15 text-red-400 border-red-500/40",
  },
  approval: {
    icon: ShieldAlert,
    label: "requires approval",
    chip: "bg-amber-500/15 text-amber-400 border-amber-500/40",
  },
  permitted: {
    icon: Check,
    label: "permitted",
    chip: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40",
  },
};

export function PayloadRegistry() {
  return (
    <section
      aria-labelledby="payload-registry-heading"
      className="rounded-lg border border-zinc-800 bg-card/60 p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="payload-registry-heading" className="text-sm font-semibold tracking-tight">
          Destructive Payload Registry
        </h3>
        <span className="rounded-sm border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-400">
          static · spec §7.3
        </span>
      </div>
      <p className="mt-1 text-xs text-zinc-500">
        Payloads with state-changing semantics are class-tagged and denied unless policy + per-target
        ticketed approval exists (Jira/ServiceNow).
      </p>

      <ul className="mt-4 divide-y divide-zinc-800/70" aria-label="Payload classes">
        {PAYLOAD_CLASSES.map((cls) => {
          const meta = VERDICT_META[cls.verdict];
          const Icon = meta.icon;
          return (
            <li key={cls.name} className="flex items-center justify-between gap-3 py-2.5">
              <span className="font-mono text-xs text-zinc-300">{cls.name}</span>
              <span
                className={cn(
                  "flex shrink-0 items-center gap-1.5 rounded-sm border px-2 py-0.5 text-[10px]",
                  meta.chip
                )}
              >
                <Icon className="h-3 w-3" aria-hidden />
                {meta.label}
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
