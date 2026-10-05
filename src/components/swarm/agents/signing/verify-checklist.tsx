"use client";

// ─── Verification checklist — staggered reveal of Sigstore/SLSA steps ────────

import { AnimatePresence, motion } from "framer-motion";
import { Check, Minus, X } from "lucide-react";
import type { SignVerifyStep } from "@/lib/swarm/types";
import { cn } from "@/lib/swarm/format";

export function VerifyChecklist({
  steps,
  verifying,
}: {
  steps: SignVerifyStep[];
  verifying: boolean;
}) {
  return (
    <ol className="space-y-1.5" aria-label="Verification steps">
      <AnimatePresence initial={false}>
        {steps.map((s, i) => (
          <motion.li
            key={s.label}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: verifying ? 0 : i * 0.13, duration: 0.22 }}
            className={cn(
              "flex items-start gap-2.5 rounded-md border px-2.5 py-2",
              s.status === "passed"
                ? "border-emerald-500/25 bg-emerald-500/[0.05]"
                : s.status === "failed"
                  ? "border-red-500/30 bg-red-500/[0.06]"
                  : "border-zinc-800 bg-zinc-900/40"
            )}
          >
            <span
              className={cn(
                "mt-0.5 flex h-4.5 w-4.5 shrink-0 items-center justify-center rounded-full",
                s.status === "passed"
                  ? "bg-emerald-500/15 text-emerald-400"
                  : s.status === "failed"
                    ? "bg-red-500/15 text-red-400"
                    : "bg-zinc-800 text-zinc-500"
              )}
              aria-hidden
            >
              {s.status === "passed" ? (
                <Check className="h-3 w-3" />
              ) : s.status === "failed" ? (
                <X className="h-3 w-3" />
              ) : (
                <Minus className="h-3 w-3" />
              )}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span
                  className={cn(
                    "text-xs font-medium leading-tight",
                    s.status === "failed" ? "text-red-300" : "text-zinc-200"
                  )}
                >
                  {s.label}
                </span>
                <span className="font-mono text-[9px] text-zinc-600">{s.ms} ms</span>
              </div>
              <p
                className={cn(
                  "mt-0.5 break-words text-[10.5px] leading-snug",
                  s.status === "failed"
                    ? "text-red-400/90"
                    : s.status === "skipped"
                      ? "text-zinc-600"
                      : "text-zinc-400"
                )}
              >
                {s.detail}
              </p>
            </div>
            <span className="sr-only">
              {s.status === "passed" ? "passed" : s.status === "failed" ? "failed" : "skipped"}
            </span>
          </motion.li>
        ))}
      </AnimatePresence>
      {verifying && (
        <motion.li
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex items-center gap-2.5 rounded-md border border-primary/25 bg-primary/[0.04] px-2.5 py-2"
        >
          <span className="h-4.5 w-4.5 shrink-0 rounded-full border-2 border-primary/30 border-t-primary animate-spin" aria-hidden />
          <span className="text-xs text-zinc-300">
            verifying — Fulcio chain, ed25519 signature, Rekor inclusion, SLSA provenance…
          </span>
        </motion.li>
      )}
    </ol>
  );
}
