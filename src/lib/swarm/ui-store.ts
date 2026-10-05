"use client";

// ─── SwarmScan UI navigation store ───────────────────────────────────────────

import { create } from "zustand";

import type { AccessRole } from "@/lib/swarm/types";

export type SwarmView =
  | "overview"
  | "targets"
  | "scans"
  | "findings"
  | "attack-graph"
  | "graph"
  | "ledger"
  | "agents"
  | "benchmark"
  | "policies"
  | "reports"
  | "compliance"
  | "integrations"
  | "access";

interface SwarmUiState {
  view: SwarmView;
  scanId: string | null; // selected scan (opens detail)
  findingId: string | null; // selected finding (opens detail)
  actingRole: AccessRole; // RBAC role simulation (permission gating across UI)
  setView: (view: SwarmView) => void;
  openScan: (scanId: string) => void;
  closeScan: () => void;
  openFinding: (findingId: string) => void;
  closeFinding: () => void;
  setActingRole: (role: AccessRole) => void;
}

export const useSwarmUi = create<SwarmUiState>((set) => ({
  view: "overview",
  scanId: null,
  findingId: null,
  actingRole: "owner",
  setView: (view) => set({ view, scanId: null, findingId: null }),
  openScan: (scanId) => set({ view: "scans", scanId, findingId: null }),
  closeScan: () => set({ scanId: null }),
  openFinding: (findingId) => set({ findingId }),
  closeFinding: () => set({ findingId: null }),
  setActingRole: (role) => set({ actingRole: role }),
}));
