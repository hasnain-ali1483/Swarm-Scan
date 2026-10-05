"use client";

// ─── Shared ["ci-gates"] query hook ──────────────────────────────────────────
// Consumed by the Benchmark view's Release CI gates section and the
// Integrations view's compact gate strip. TanStack Query dedupes concurrent
// fetches under the same key, so both surfaces share one 30s-polling cache.

import { useQuery } from "@tanstack/react-query";
import { api, type CiGatesResponse } from "@/lib/swarm/types";

export function useCiGates() {
  return useQuery({
    queryKey: ["ci-gates"],
    queryFn: () => api<CiGatesResponse>("/api/ci-gates"),
    refetchInterval: 30_000,
  });
}
