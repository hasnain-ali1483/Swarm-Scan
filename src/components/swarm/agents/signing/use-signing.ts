"use client";

// ─── Supply-chain signing — query + verify mutation (Task 10-b) ─────────────

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { api, type SignVerifyResponse, type SigningResponse } from "@/lib/swarm/types";

export function useSigning() {
  return useQuery({
    queryKey: ["signing"],
    queryFn: () => api<SigningResponse>("/api/signing"),
    refetchInterval: 120_000,
  });
}

export function useBundleVerify() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (input: { agentKey: string; releaseTag: string }) =>
      api<SignVerifyResponse>("/api/signing/verify", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    onSuccess: async (res) => {
      toast({
        title: res.verified
          ? `Signature verified — ${res.releaseTag}`
          : `Verification FAILED — ${res.releaseTag}`,
        description: res.verified
          ? `Sigstore + SLSA checks passed in ${res.durationMs} ms`
          : `${res.steps.find((s) => s.status === "failed")?.label ?? "verification"} failed`,
        variant: res.verified ? "default" : "destructive",
      });
      await queryClient.invalidateQueries({ queryKey: ["signing"] });
    },
    onError: (err: Error) => {
      toast({
        title: "Verification error",
        description: err.message,
        variant: "destructive",
      });
    },
  });
}
