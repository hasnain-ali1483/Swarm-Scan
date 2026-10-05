"use client";

// ─── Integrations data hooks — catalog query, mutations, activity feed ────────
// Wraps the /api/integrations surface (contract in src/lib/swarm/types.ts).
// ok:false test/connect results are VALID responses and never toast — the
// connector dialog renders them in its result panel. Only transport/4xx/5xx
// errors toast.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import {
  api,
  type IntegrationActivityResponse,
  type IntegrationConnectPayload,
  type IntegrationDispatchPayload,
  type IntegrationDispatchResponse,
  type IntegrationItem,
  type IntegrationsResponse,
  type IntegrationSyncResponse,
  type IntegrationTestResponse,
  type IntegrationUpdateResponse,
} from "@/lib/swarm/types";

/** Catalog snapshot — 47 connectors with live connection state. */
export function useIntegrations() {
  return useQuery({
    queryKey: ["integrations"],
    queryFn: () => api<IntegrationsResponse>("/api/integrations"),
    refetchInterval: 15_000,
  });
}

/**
 * Pull the server's `{ error }` message out of the api() helper's
 * `403 Forbidden — {"error":"…"}` Error message. Falls back to the raw
 * message, then to a generic control-plane failure line.
 */
export function extractApiError(e: unknown): string {
  const message = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  const dash = message.indexOf("— ");
  if (dash >= 0) {
    const jsonPart = message.slice(dash + 2).trim();
    try {
      const parsed = JSON.parse(jsonPart) as { error?: string };
      if (parsed && typeof parsed.error === "string" && parsed.error) return parsed.error;
    } catch {
      // not a JSON body — fall through to the raw message
    }
  }
  return message || "Control plane unreachable";
}

export function useIntegrationMutations() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["integrations"] });
    void queryClient.invalidateQueries({ queryKey: ["integration-activity"] });
  };

  // Enable/disable. The SERVER gates enabling on a complete config + passing
  // test — a 409 toasts the exact reason ("no connection test on record…").
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api<IntegrationUpdateResponse>(`/api/integrations/${id}`, {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: ({ integration, notice }, { enabled }) => {
      toast({
        title: `${integration.name} ${enabled ? "connected" : "disconnected"}`,
        description:
          notice ??
          (enabled
            ? `Verified ${integration.lastTest ? `${integration.lastTest.latencyMs}ms round-trip` : ""} — dispatches are dedupe-guarded and rate-limited by its guardrails.`
            : "Streaming paused. Dispatched tickets, alerts and synced records are retained."),
      });
      refresh();
    },
    onError: (e) => {
      toast({
        title: "Connection change rejected",
        description: extractApiError(e),
        variant: "destructive",
      });
    },
  });

  const saveConfig = useMutation({
    mutationFn: ({ id, config }: { id: string; config: Record<string, string> }) =>
      api<IntegrationUpdateResponse>(`/api/integrations/${id}`, {
        method: "PUT",
        body: JSON.stringify({ config }),
      }),
    onSuccess: ({ integration, autoDisabled, notice }) => {
      toast({
        title: "Configuration saved",
        description:
          notice ??
          (autoDisabled
            ? "Config changed — the connector stays disconnected until re-verified."
            : "Stored server-side — secret values stay redacted in every response and tests use the stored config."),
      });
      refresh();
    },
    onError: (e) => {
      toast({
        title: "Configuration save failed",
        description: extractApiError(e),
        variant: "destructive",
      });
    },
  });

  // Guided flow: save (optional patch) → test → enable only on pass.
  // ok:false is a successful round-trip — the dialog renders the result panel.
  const connect = useMutation({
    mutationFn: ({ id, config }: { id: string; config?: Record<string, string> }) =>
      api<{ ok: boolean; test: IntegrationTestResponse; integration: IntegrationItem; autoDisabled?: boolean; error?: string }>(
        `/api/integrations/${id}/connect`,
        {
          method: "POST",
          body: JSON.stringify({ ...(config ? { config } : {}) } satisfies IntegrationConnectPayload),
        }
      ),
    onSuccess: (res) => {
      if (res.ok) {
        toast({
          title: `${res.integration.name} connected`,
          description: `Verification passed in ${res.test.latencyMs}ms — the connector is live and guardrail-enforced.`,
        });
      }
      refresh();
    },
    onError: (e) => {
      toast({
        title: "Connect could not run",
        description: extractApiError(e),
        variant: "destructive",
      });
    },
  });

  // ok:false is a successful round-trip — the dialog renders the result panel.
  const test = useMutation({
    mutationFn: ({ id }: { id: string }) =>
      api<IntegrationTestResponse>(`/api/integrations/${id}/test`, {
        method: "POST",
        body: JSON.stringify({}),
      }),
    onSuccess: () => refresh(),
    onError: (e) => {
      toast({
        title: "Test could not run",
        description: extractApiError(e),
        variant: "destructive",
      });
    },
  });

  const dispatch = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: IntegrationDispatchPayload }) =>
      api<IntegrationDispatchResponse>(`/api/integrations/${id}/dispatch`, {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => refresh(),
    onError: (e) => {
      toast({
        title: "Dispatch rejected",
        description: extractApiError(e),
        variant: "destructive",
      });
    },
  });

  const sync = useMutation({
    mutationFn: ({ id }: { id: string }) =>
      api<IntegrationSyncResponse>(`/api/integrations/${id}/sync`, {
        method: "POST",
        body: JSON.stringify({}),
      }),
    onSuccess: () => refresh(),
    onError: (e) => {
      toast({
        title: "Sync failed",
        description: extractApiError(e),
        variant: "destructive",
      });
    },
  });

  return { toggle, saveConfig, connect, test, dispatch, sync };
}

/** Per-connector audit trail — enabled only while a connector dialog is open. */
export function useIntegrationActivity(id: string | null) {
  return useQuery({
    queryKey: ["integration-activity", id],
    queryFn: () => api<IntegrationActivityResponse>(`/api/integrations/${id}/activity`),
    enabled: !!id,
    refetchInterval: 20_000,
  });
}
