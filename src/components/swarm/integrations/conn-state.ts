import {
  CircleDashed,
  CircleSlash,
  CircleX,
  Plug,
  PlugZap,
  type LucideIcon,
} from "lucide-react";
import type { IntegrationConnState } from "@/lib/swarm/types";

/**
 * Single source of truth for rendering the truthful connection lifecycle.
 * Every surface (card switch, dialog banner, summary strip, category chips)
 * derives its label/dot/icon/colors from here so the states can never drift.
 */
export const CONN_STATE_META: Record<
  IntegrationConnState,
  {
    label: string;
    short: string;
    dot: string;
    text: string;
    chip: string;
    icon: LucideIcon;
    /** can the switch be flipped ON right now? (server double-checks anyway) */
    canEnable: boolean;
    explanation: string;
  }
> = {
  connected: {
    label: "connected",
    short: "live",
    dot: "bg-emerald-500",
    text: "text-emerald-400",
    chip: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
    icon: PlugZap,
    canEnable: true,
    explanation:
      "Enabled and verified — the stored configuration passed a live connection test.",
  },
  disabled: {
    label: "verified · off",
    short: "off",
    dot: "bg-zinc-400",
    text: "text-zinc-400",
    chip: "border-zinc-700 bg-zinc-900/60 text-zinc-400",
    icon: CircleSlash,
    canEnable: true,
    explanation:
      "Configuration verified previously — flip the switch to reconnect, no re-test needed.",
  },
  unverified: {
    label: "unverified",
    short: "unverified",
    dot: "bg-amber-500",
    text: "text-amber-400",
    chip: "border-amber-500/30 bg-amber-500/10 text-amber-400",
    icon: CircleDashed,
    canEnable: false,
    explanation:
      "Configuration looks complete but no connection test is on record — the server refuses to enable it until one passes.",
  },
  failed: {
    label: "test failed",
    short: "failed",
    dot: "bg-red-500",
    text: "text-red-400",
    chip: "border-red-500/30 bg-red-500/10 text-red-400",
    icon: CircleX,
    canEnable: false,
    explanation:
      "The most recent connection test failed — fix the listed issues and re-test before connecting.",
  },
  not_configured: {
    label: "not configured",
    short: "unset",
    dot: "bg-zinc-600",
    text: "text-zinc-500",
    chip: "border-zinc-800 bg-zinc-900/40 text-zinc-500",
    icon: Plug,
    canEnable: false,
    explanation:
      "Required connection fields are missing — open Configure and fill them in before testing.",
  },
};
