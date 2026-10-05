"use client";

// ─── Shared compliance queries + mutations (Task 11-b) ───────────────────────

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import {
  api,
  type ComplianceExportOptions,
  type ComplianceExportResponse,
  type CompliancePack,
  type SchedulerListResponse,
} from "@/lib/swarm/types";

/** SOC 2 evidence pack — assembled live from the WORM ledger. */
export function useCompliance() {
  return useQuery({
    queryKey: ["compliance"],
    queryFn: () => api<CompliancePack>("/api/compliance"),
    staleTime: 30_000,
    refetchInterval: 120_000,
  });
}

/** Export scheduler jobs — 15 s poll keeps countdowns / next-run fresh. */
export function useScheduler() {
  return useQuery({
    queryKey: ["scheduler"],
    queryFn: () => api<SchedulerListResponse>("/api/scheduler"),
    refetchInterval: 15_000,
  });
}

/** Ticking "now" for live countdowns (re-renders every `intervalMs`). */
export function useNow(intervalMs = 1_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}

/** Seals an export pack: toasts, saves the JSON receipt as a blob download. */
export function useExportPack() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (options: ComplianceExportOptions) =>
      api<ComplianceExportResponse>("/api/compliance/export", {
        method: "POST",
        body: JSON.stringify(options),
      }),
    onSuccess: async (res) => {
      const body = JSON.stringify(res, null, 2);
      const blob = new Blob([body], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = res.fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast({
        title: "SOC 2 pack exported",
        description: `Sealed ${res.fileName} · ${(res.sizeBytes / 1024).toFixed(1)} KB · ${res.entries} entries · delivery logged to the WORM audit trail.`,
      });
      await queryClient.invalidateQueries({ queryKey: ["compliance"] });
    },
    onError: (err: Error) => {
      toast({
        title: "Export failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });
}

export interface SchedulerMutateInput {
  action: "pause" | "resume" | "run-now" | "delete" | "create";
  id?: string;
  name?: string;
  cron?: string;
  format?: string;
}

/** Scheduler mutations — toasts the engine verdict, refreshes the job list. */
export function useSchedulerMutate() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (input: SchedulerMutateInput) =>
      api<{ ok: boolean; message: string }>("/api/scheduler/mutate", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    onSuccess: async (res) => {
      if (res.ok) {
        toast({ title: "Scheduler updated", description: res.message });
      } else {
        toast({ title: "Scheduler rejected the change", description: res.message, variant: "destructive" });
      }
      await queryClient.invalidateQueries({ queryKey: ["scheduler"] });
    },
    onError: (err: Error) => {
      toast({
        title: "Scheduler mutation failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });
}
