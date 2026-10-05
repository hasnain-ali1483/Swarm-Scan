"use client";

// ─── Chain selector list: compact cards with progress + verified state ────────

import { Check } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SEVERITY_STYLES, cn, truncateMiddle } from "@/lib/swarm/format";
import type { AttackChainItem } from "@/lib/swarm/types";

export function ChainList({
  chains,
  selectedId,
  onSelect,
}: {
  chains: AttackChainItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="swarm-scroll max-h-72 space-y-2 overflow-y-auto pr-1" role="listbox" aria-label="Attack chains">
      {chains.map((chain) => {
        const active = chain.id === selectedId;
        const executed = chain.steps.filter((s) => s.status === "executed").length;
        return (
          <button
            key={chain.id}
            type="button"
            role="option"
            aria-selected={active}
            onClick={() => onSelect(chain.id)}
            className={cn(
              "w-full rounded-lg border p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/40",
              active
                ? "border-primary/60 bg-primary/5"
                : "border-border bg-card/40 hover:border-zinc-600 hover:bg-card/70"
            )}
          >
            <div className="flex items-center gap-2">
              <span className={cn("h-2 w-2 shrink-0 rounded-full", SEVERITY_STYLES[chain.severity]?.dot)} aria-hidden />
              <span className="min-w-0 flex-1 truncate text-sm font-medium text-zinc-200">{chain.name}</span>
              {chain.verified ? (
                <Badge variant="outline" className="gap-0.5 border-emerald-500/40 bg-emerald-500/15 px-1.5 py-0 text-[9px] text-emerald-400">
                  <Check className="h-2.5 w-2.5" aria-hidden />
                  Verified
                </Badge>
              ) : (
                <Badge variant="outline" className="border-amber-500/40 bg-amber-500/15 px-1.5 py-0 text-[9px] text-amber-400">
                  Unverified
                </Badge>
              )}
            </div>
            <div className="mt-1.5 flex items-center justify-between gap-2">
              <span className="min-w-0 truncate font-mono text-[10px] text-zinc-500" title={chain.scanId}>
                scan {truncateMiddle(chain.scanId, 14)}
              </span>
              <span className="shrink-0 font-mono text-[10px] text-zinc-400">
                {executed}/{chain.steps.length}
              </span>
            </div>
          </button>
        );
      })}
    </div>
  );
}
