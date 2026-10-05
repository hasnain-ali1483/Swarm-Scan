"use client";

// ─── Stable engine socket subscription ───────────────────────────────────────
// useEngineSocket().on re-creates its api object on every engine:stats tick,
// which would churn useEffect deps if consumed naively. This hook pins the
// subscription once per event name and always invokes the latest handler.

import { useEffect, useRef } from "react";
import {
  useEngineSocket,
  type EngineEventName,
  type EngineEventPayloads,
} from "@/components/swarm/providers";

export function useEngineSub<E extends EngineEventName>(
  event: E,
  handler: (payload: EngineEventPayloads[E]) => void
): void {
  const { on } = useEngineSocket();
  const onRef = useRef(on);
  const handlerRef = useRef(handler);

  // Keep refs fresh without touching them during render.
  useEffect(() => {
    onRef.current = on;
    handlerRef.current = handler;
  });

  useEffect(() => {
    // The provider's `on` closes over a stable handler-set ref, so the
    // subscription made on first mount stays live for the app lifetime.
    return onRef.current(event, (payload) => handlerRef.current(payload));
  }, [event]);
}
