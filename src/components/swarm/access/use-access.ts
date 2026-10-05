"use client";

// ─── Shared ["access"] query + mutation hook (Task 9-b) ─────────────────────

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { api, type AccessAction, type AccessMutationResponse, type AccessResponse } from "@/lib/swarm/types";

export function useAccess() {
  return useQuery({
    queryKey: ["access"],
    queryFn: () => api<AccessResponse>("/api/access"),
    refetchInterval: 60_000,
  });
}

/**
 * Mutations against the Action union. Invalidates ["access"] and toasts the
 * server's verdict message. Returns the response so callers can surface
 * key.create's one-time secret.
 */
export function useAccessMutation() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: (action: AccessAction) =>
      api<AccessMutationResponse>("/api/access", {
        method: "POST",
        body: JSON.stringify(action),
      }),
    onSuccess: async (res) => {
      if (res.ok) {
        toast({ title: "Access control updated", description: res.message });
      } else {
        toast({ title: "Change rejected", description: res.message, variant: "destructive" });
      }
      await queryClient.invalidateQueries({ queryKey: ["access"] });
    },
    onError: (err: Error) => {
      toast({
        title: "Access mutation failed",
        description: err.message,
        variant: "destructive",
      });
    },
  });
}
