"use client";

// ─── Chain steps panel: vertical stepper with approval gates ─────────────────
// "Approve & execute step n+1" → POST /api/attack-chains/[id]/verify →
// response { chain } replaces the cached chain; toasts on step execution and
// on full verification.

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { AlertTriangle, Check, Loader2, Play, ShieldCheck } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { SEVERITY_STYLES, cn } from "@/lib/swarm/format";
import { api, type AttackChainItem, type AttackGraphResponse } from "@/lib/swarm/types";

function StepCircle({ index, status, isCurrent }: { index: number; status: string; isCurrent: boolean }) {
  if (status === "executed") {
    return (
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-emerald-500/50 bg-emerald-500/15 text-emerald-400">
        <Check className="h-3.5 w-3.5" aria-hidden />
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-red-500/50 bg-red-500/15 text-red-400">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
      </span>
    );
  }
  return (
    <span
      className={cn(
        "flex h-7 w-7 shrink-0 items-center justify-center rounded-full border font-mono text-[11px]",
        isCurrent
          ? "swarm-pulse border-emerald-500/60 bg-emerald-500/10 text-emerald-400 ring-2 ring-emerald-500/30"
          : "border-zinc-700 bg-zinc-900 text-zinc-500"
      )}
    >
      {index + 1}
    </span>
  );
}

export function StepsPanel({ chain }: { chain: AttackChainItem }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const executeMutation = useMutation({
    mutationFn: async () => {
      const step = chain.steps[chain.currentStep];
      const stepTitle = step?.title ?? `step ${chain.currentStep + 1}`;
      const wasVerified = chain.verified;
      const res = await api<{ chain: AttackChainItem }>(`/api/attack-chains/${chain.id}/verify`, {
        method: "POST",
      });
      return { res, stepTitle, wasVerified };
    },
    onSuccess: ({ res, stepTitle, wasVerified }) => {
      queryClient.setQueryData<AttackGraphResponse>(["attack-graph"], (old) =>
        old ? { chains: old.chains.map((c) => (c.id === res.chain.id ? res.chain : c)) } : old
      );
      if (res.chain.verified && !wasVerified) {
        toast({
          title: "Attack chain fully verified — impact confirmed",
          description: `Step executed: ${stepTitle}. Every step of "${res.chain.name}" is now machine-verified against the target.`,
        });
      } else {
        toast({
          title: `Step executed: ${stepTitle}`,
          description: "Verification evidence appended to the WORM ledger.",
        });
      }
    },
    onError: (err) => {
      toast({
        title: "Step execution failed",
        description: err instanceof Error ? err.message : "Engine unreachable",
        variant: "destructive",
      });
    },
  });

  const executedCount = chain.steps.filter((s) => s.status === "executed").length;
  const allDone = chain.verified || chain.currentStep >= chain.steps.length;
  const hasFailure = chain.steps.some((s) => s.status === "failed");

  return (
    <Card className="gap-4">
      <CardHeader className="pb-0">
        <CardTitle className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
          <span className="min-w-0 truncate">{chain.name}</span>
          <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px] uppercase", SEVERITY_STYLES[chain.severity]?.badge ?? "")}>
            {SEVERITY_STYLES[chain.severity]?.label ?? chain.severity}
          </Badge>
          {chain.verified ? (
            <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/15 px-1.5 py-0 text-[10px] text-emerald-400">
              <Check className="h-3 w-3" aria-hidden />
              Verified
            </Badge>
          ) : (
            <Badge variant="outline" className="border-amber-500/40 bg-amber-500/15 px-1.5 py-0 text-[10px] text-amber-400">
              Unverified
            </Badge>
          )}
        </CardTitle>
        <CardDescription className="flex items-center gap-2 text-xs">
          <span className="font-mono text-zinc-400">
            {executedCount}/{chain.steps.length} steps executed
          </span>
          <span className="text-zinc-600" aria-hidden>·</span>
          <span>policy-gated verification plan</span>
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* stepper */}
        <ol>
          {chain.steps.map((step, i) => {
            const isCurrent = i === chain.currentStep && !allDone;
            return (
              <li key={`${i}-${step.title}`} className="relative flex gap-3 pb-4 last:pb-0">
                {i < chain.steps.length - 1 ? (
                  <span
                    className={cn(
                      "absolute bottom-0 left-[13.5px] top-8 w-px",
                      step.status === "executed" ? "bg-emerald-500/40" : "bg-zinc-800"
                    )}
                    aria-hidden
                  />
                ) : null}
                <StepCircle index={i} status={step.status} isCurrent={isCurrent} />
                <div className={cn("min-w-0 flex-1 rounded-md px-2 py-1 -mx-2", isCurrent && "bg-emerald-500/[0.06]")}>
                  <div className="flex items-baseline justify-between gap-2">
                    <p className={cn("truncate text-sm", isCurrent ? "font-medium text-emerald-300" : "text-zinc-200")}>
                      {step.title}
                    </p>
                    <span
                      className={cn(
                        "shrink-0 text-[10px] font-medium uppercase tracking-wider",
                        step.status === "executed"
                          ? "text-emerald-500"
                          : step.status === "failed"
                            ? "text-red-400"
                            : "text-zinc-500"
                      )}
                    >
                      {step.status}
                    </span>
                  </div>
                  <p className="mt-0.5 break-all font-mono text-[11px] leading-relaxed text-zinc-500">{step.action}</p>
                </div>
              </li>
            );
          })}
        </ol>

        {/* CTA / verified panel */}
        {allDone ? (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-start gap-2.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 p-3"
            role="status"
          >
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
            <p className="text-xs leading-relaxed text-emerald-300">
              Chain verified — every step machine-verified against the target.
            </p>
          </motion.div>
        ) : hasFailure ? (
          <div className="flex items-start gap-2.5 rounded-md border border-red-500/40 bg-red-500/10 p-3" role="alert">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" aria-hidden />
            <p className="text-xs leading-relaxed text-red-400">
              A verification step failed — the chain is halted pending operator review.
            </p>
          </div>
        ) : (
          <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
            <AlertDialogTrigger asChild>
              <Button className="w-full gap-2" disabled={executeMutation.isPending} aria-label={`Approve and execute step ${chain.currentStep + 1}`}>
                {executeMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                ) : (
                  <Play className="h-4 w-4" aria-hidden />
                )}
                {executeMutation.isPending
                  ? "Executing…"
                  : `Approve & execute step ${chain.currentStep + 1}`}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  Execute verification step {chain.currentStep + 1}?
                </AlertDialogTitle>
                <AlertDialogDescription>
                  This executes a policy-permitted verification step against the target. Continue?
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={(e) => {
                    e.preventDefault();
                    setConfirmOpen(false);
                    executeMutation.mutate();
                  }}
                >
                  Approve & execute
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}
        {executeMutation.isPending ? <p className="sr-only" role="status">Executing verification step…</p> : null}
      </CardContent>
    </Card>
  );
}
