"use client";

// ─── New Scan wizard — 2-step dialog ─────────────────────────────────────────
// Step 1: target · profile · policy tier · deterministic seed
// Step 2: DAG agent selection grouped by execution stage

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ArrowRight, Check, Crosshair, Dices, Globe, Loader2, Lock, Network, Radar, ShieldAlert, Zap } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";
import { AGENT_BY_KEY, DYNAMIC_AGENT_KEYS } from "@/lib/swarm/agents-catalog";
import { cn, truncateMiddle } from "@/lib/swarm/format";
import {
  api,
  type CreateScanPayload,
  type PolicyTier,
  type ScanProfile,
  type ScanSummary,
  type TargetItem,
} from "@/lib/swarm/types";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import {
  ALL_AGENT_KEYS,
  agentsInStage,
  defaultAgentsFor,
  isDataTouching,
  QUICK_AGENT_KEYS,
  STAGES,
  STAGE_LABELS,
} from "./stages";

const PROFILES: { value: ScanProfile; title: string; desc: string }[] = [
  { value: "quick", title: "Quick", desc: "6 agents · fast triage" },
  { value: "full", title: "Full", desc: `All ${ALL_AGENT_KEYS.length} agents · deep coverage` },
  { value: "continuous", title: "Continuous", desc: "Full + revisit queue · continuous assurance" },
];

const DYNAMIC_AGENTS_WIZARD = DYNAMIC_AGENT_KEYS.map((k) => AGENT_BY_KEY[k]);

const TIERS: { value: PolicyTier; title: string; desc: string; border: string }[] = [
  {
    value: "safe",
    title: "Safe",
    desc: "read-only agents only — data-touching blocked",
    border: "border-l-emerald-500",
  },
  {
    value: "standard",
    title: "Standard",
    desc: "two-technique verification, no destructive payloads",
    border: "border-l-zinc-500",
  },
  {
    value: "aggressive",
    title: "Aggressive",
    desc: "escalation approved — data-exfil PoC within scope",
    border: "border-l-amber-500",
  },
];

function randomSeed(): string {
  return Array.from(
    { length: 16 },
    () => "0123456789abcdef"[Math.floor(Math.random() * 16)]
  ).join("");
}

function OptionCard({
  selected,
  onSelect,
  title,
  desc,
  leftBorder,
  badge,
  disabled,
}: {
  selected: boolean;
  onSelect: () => void;
  title: string;
  desc: string;
  leftBorder?: string;
  badge?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      aria-disabled={disabled}
      disabled={disabled}
      onClick={onSelect}
      className={cn(
        "relative rounded-lg border p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary",
        leftBorder,
        disabled
          ? "cursor-not-allowed border-border/60 bg-muted/20 opacity-45"
          : selected
            ? "border-primary/50 bg-primary/10"
            : "border-border bg-muted/30 hover:border-zinc-600 hover:bg-muted/50"
      )}
    >
      <span className="flex items-center justify-between gap-2">
        <span className="text-[13px] font-semibold text-foreground">{title}</span>
        {badge && (
          <span className="font-mono text-[10px] text-muted-foreground">{badge}</span>
        )}
      </span>
      <span className="mt-1 block text-[11px] leading-4 text-muted-foreground">
        {desc}
      </span>
      {selected && (
        <span className="absolute right-2 top-2 flex h-4 w-4 items-center justify-center rounded-full bg-primary">
          <Check className="h-2.5 w-2.5 text-primary-foreground" aria-hidden />
        </span>
      )}
    </button>
  );
}

export function NewScanDialog({
  open,
  onOpenChange,
  onLaunched,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onLaunched: (scan: ScanSummary) => void;
}) {
  const { toast } = useToast();
  const setView = useSwarmUi((s) => s.setView);
  const actingRole = useSwarmUi((s) => s.actingRole);
  const isOwner = actingRole === "owner";
  const [step, setStep] = useState(1);
  const [targetId, setTargetId] = useState<string>("");
  const [profile, setProfile] = useState<ScanProfile>("quick");
  const [tier, setTier] = useState<PolicyTier>("standard");
  const [seed, setSeed] = useState("");
  const [selected, setSelected] = useState<string[]>(defaultAgentsFor("quick"));
  const [targetError, setTargetError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);

  // Scans launch only against a registered, AUTHORIZED target (prerequisite).
  const { data: targets = [] } = useQuery({
    queryKey: ["targets"],
    queryFn: () => api<TargetItem[]>("/api/targets"),
    enabled: open,
  });
  const authorizedTargets = useMemo(() => targets.filter((t) => t.authorized), [targets]);
  const selectedTarget = authorizedTargets.find((t) => t.id === targetId) ?? null;

  // Reopening always starts at step 1.
  useEffect(() => {
    if (open) setStep(1);
  }, [open]);

  // Safe tier locks out data-touching agents.
  useEffect(() => {
    if (tier === "safe") {
      setSelected((prev) => prev.filter((k) => !isDataTouching(k)));
    }
  }, [tier]);

  // Destructive-oracle gate: the aggressive tier is Owner-exclusive. A non-Owner
  // can never hold it selected.
  useEffect(() => {
    if (!isOwner && tier === "aggressive") setTier("standard");
  }, [isOwner, tier]);

  const targetValid = selectedTarget !== null;

  const applyProfile = (p: ScanProfile) => {
    setProfile(p);
    setSelected(defaultAgentsFor(p));
  };

  const goToStep2 = () => {
    if (!targetValid) {
      setTargetError("Select an authorized target to scan");
      return;
    }
    setTargetError(null);
    setStep(2);
  };

  const toggleAgent = (key: string) => {
    if (tier === "safe" && isDataTouching(key)) return;
    setSelected((prev) =>
      prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]
    );
  };

  const selectAllAllowed = () => {
    setSelected(
      Object.values(AGENT_BY_KEY)
        .filter((a) => tier !== "safe" || a.safetyClass === "read-only")
        .map((a) => a.key)
    );
  };

  const resetToProfile = () => {
    setSelected(
      defaultAgentsFor(profile).filter((k) => tier !== "safe" || !isDataTouching(k))
    );
  };

  const launch = async () => {
    if (!selectedTarget || selected.length === 0) return;
    setLaunching(true);
    try {
      const payload: CreateScanPayload = {
        targetId: selectedTarget.id,
        profile,
        policyTier: tier,
        actingRole,
        ...(seed.trim() ? { seed: seed.trim() } : {}),
        agents: selected,
      };
      const scan = await api<ScanSummary>("/api/scans", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast({
        title: "Scan launched",
        description: "DAG plan dispatched to execution plane.",
      });
      onOpenChange(false);
      onLaunched(scan);
    } catch (err) {
      toast({
        title: "Launch failed",
        description: err instanceof Error ? err.message : "Engine unreachable",
        variant: "destructive",
      });
    } finally {
      setLaunching(false);
    }
  };

  const summary =
    `${selected.length} agent${selected.length === 1 ? "" : "s"} · ${profile} · ${tier} tier` +
    (seed.trim() ? ` · seed ${truncateMiddle(seed.trim(), 12)}` : "");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[88vh] w-[calc(100vw-2rem)] overflow-y-auto swarm-scroll sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            New Scan Plan
            <span className="flex items-center gap-1 font-mono text-[10px] font-normal text-muted-foreground">
              <span
                className={cn(
                  "rounded border px-1.5 py-px uppercase tracking-wider",
                  step === 1
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-zinc-700 text-zinc-500"
                )}
              >
                1 · Plan
              </span>
              <span
                className={cn(
                  "rounded border px-1.5 py-px uppercase tracking-wider",
                  step === 2
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-zinc-700 text-zinc-500"
                )}
              >
                2 · Agents
              </span>
            </span>
          </DialogTitle>
          <DialogDescription className="text-xs">
            {step === 1
              ? "Target, profile, policy tier and deterministic seed."
              : "Select the agents for the DAG plan — grouped by execution stage."}
          </DialogDescription>
        </DialogHeader>

        {step === 1 ? (
          <motion.div
            key="step1"
            initial={{ opacity: 0, x: 12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="space-y-5"
          >
            <div className="space-y-1.5">
              <Label className="text-xs">
                Authorized target <span className="text-red-400">*</span>
              </Label>
              {authorizedTargets.length === 0 ? (
                <div className="flex flex-col items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                  <p className="flex items-center gap-1.5 text-[12px] font-medium text-amber-300">
                    <ShieldAlert className="h-3.5 w-3.5" aria-hidden /> No authorized targets
                  </p>
                  <p className="text-[11px] leading-5 text-muted-foreground">
                    Registering and authorizing a target is a prerequisite for scanning. Add one in Targets.
                  </p>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-7 text-[11px]"
                    onClick={() => {
                      onOpenChange(false);
                      setView("targets");
                    }}
                  >
                    <Crosshair className="mr-1 h-3 w-3" aria-hidden /> Go to Targets
                  </Button>
                </div>
              ) : (
                <div role="radiogroup" aria-label="Authorized target" className="grid max-h-56 gap-1.5 overflow-y-auto swarm-scroll">
                  {authorizedTargets.map((t) => {
                    const active = t.id === targetId;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        role="radio"
                        aria-checked={active}
                        onClick={() => {
                          setTargetId(t.id);
                          if (targetError) setTargetError(null);
                        }}
                        className={cn(
                          "flex items-center gap-2.5 rounded-lg border p-2.5 text-left transition-colors",
                          active ? "border-primary/50 bg-primary/10" : "border-border bg-muted/30 hover:border-zinc-600"
                        )}
                      >
                        <span className={cn("flex h-6 w-6 shrink-0 items-center justify-center rounded-md border", t.scope === "internal" ? "border-sky-500/30 bg-sky-500/10 text-sky-400" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400")}>
                          {t.scope === "internal" ? <Network className="h-3 w-3" aria-hidden /> : <Globe className="h-3 w-3" aria-hidden />}
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-[13px] font-medium text-foreground">{t.name}</span>
                          <span className="block truncate font-mono text-[11px] text-muted-foreground">{t.value}</span>
                        </span>
                        <span className="shrink-0 font-mono text-[9px] uppercase tracking-wide text-muted-foreground">{t.scope}</span>
                        {active && (
                          <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-primary">
                            <Check className="h-2.5 w-2.5 text-primary-foreground" aria-hidden />
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
              {targetError && (
                <p className="text-[11px] text-red-400" role="alert">
                  {targetError}
                </p>
              )}
            </div>

            <fieldset className="space-y-2">
              <legend className="mb-1 text-xs font-medium text-foreground">Profile</legend>
              <div
                role="radiogroup"
                aria-label="Scan profile"
                className="grid gap-2 sm:grid-cols-3"
              >
                {PROFILES.map((p) => (
                  <OptionCard
                    key={p.value}
                    selected={profile === p.value}
                    onSelect={() => applyProfile(p.value)}
                    title={p.title}
                    desc={p.desc}
                  />
                ))}
              </div>
            </fieldset>

            <fieldset className="space-y-2">
              <legend className="mb-1 text-xs font-medium text-foreground">
                Policy tier
              </legend>
              <div
                role="radiogroup"
                aria-label="Policy tier"
                className="grid gap-2 border-l-2 border-transparent sm:grid-cols-3"
              >
                {TIERS.map((t) => {
                  const ownerLocked = t.value === "aggressive" && !isOwner;
                  return (
                    <OptionCard
                      key={t.value}
                      selected={tier === t.value}
                      onSelect={() => {
                        if (ownerLocked) return;
                        setTier(t.value);
                      }}
                      title={t.title}
                      desc={ownerLocked ? "destructive-oracle class — Owner only" : t.desc}
                      leftBorder={`border-l-2 ${t.border}`}
                      badge={ownerLocked ? "owner only" : undefined}
                      disabled={ownerLocked}
                    />
                  );
                })}
              </div>
              {!isOwner && (
                <p className="text-[11px] text-muted-foreground">
                  Aggressive (destructive-oracle) scans are Owner-exclusive — data-touching / RCE / exfil probes cannot be authorized by Admin or below.
                </p>
              )}
            </fieldset>

            <div className="space-y-1.5">
              <Label htmlFor="scan-seed" className="text-xs">
                Deterministic seed{" "}
                <span className="font-normal text-muted-foreground">(optional)</span>
              </Label>
              <div className="relative">
                <Input
                  id="scan-seed"
                  value={seed}
                  onChange={(e) => setSeed(e.target.value)}
                  placeholder="deterministic seed — same seed ⇒ identical probe sequence"
                  className="pr-10 font-mono text-xs"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="absolute right-1 top-1 h-7 w-7 text-muted-foreground hover:text-foreground"
                  aria-label="Randomize seed"
                  onClick={() => setSeed(randomSeed())}
                >
                  <Dices className="h-4 w-4" aria-hidden />
                </Button>
              </div>
            </div>
          </motion.div>
        ) : (
          <motion.div
            key="step2"
            initial={{ opacity: 0, x: 12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="space-y-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-xs text-zinc-400">
                {selected.length}/15 selected
                {tier === "safe" && (
                  <span className="ml-2 text-emerald-400">· 7 data-touching locked</span>
                )}
              </span>
              <span className="flex gap-1.5">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-7 text-[11px]"
                  onClick={selectAllAllowed}
                >
                  Select all
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-7 text-[11px]"
                  onClick={resetToProfile}
                >
                  Reset
                </Button>
              </span>
            </div>

            {STAGES.map((stage) => (
              <section key={stage} aria-label={`Stage ${stage} agents`}>
                <h4 className="mb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  Stage {stage} — {STAGE_LABELS[stage]}
                </h4>
                <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
                  {agentsInStage(stage)
                    .filter((agent) => !agent.dynamic)
                    .map((agent) => {
                    const locked = tier === "safe" && isDataTouching(agent.key);
                    const active = selected.includes(agent.key);
                    const chip = (
                      <button
                        type="button"
                        aria-pressed={active}
                        disabled={locked}
                        onClick={() => toggleAgent(agent.key)}
                        className={cn(
                          "flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary",
                          locked
                            ? "cursor-not-allowed border-border/60 bg-muted/20 opacity-45"
                            : active
                              ? "border-primary/50 bg-primary/10 text-primary-foreground"
                              : "border-border bg-muted/30 hover:border-zinc-600 hover:bg-muted/50"
                        )}
                      >
                        {locked ? (
                          <Lock className="h-3 w-3 shrink-0 text-zinc-500" aria-hidden />
                        ) : (
                          <span
                            className={cn(
                              "h-1.5 w-1.5 shrink-0 rounded-full",
                              active ? "bg-primary" : "bg-zinc-600"
                            )}
                            aria-hidden
                          />
                        )}
                        <span className="min-w-0 flex-1 truncate text-[11px] font-medium text-zinc-200">
                          {agent.name}
                        </span>
                        <span className="shrink-0 font-mono text-[9px] text-zinc-500">
                          v{agent.version}
                        </span>
                      </button>
                    );
                    return locked ? (
                      <Tooltip key={agent.key}>
                        <TooltipTrigger asChild>{chip}</TooltipTrigger>
                        <TooltipContent>
                          Blocked by safe tier — data-touching class requires approval
                        </TooltipContent>
                      </Tooltip>
                    ) : (
                      <span key={agent.key} title={`${agent.safetyClass} · ${agent.description.slice(0, 120)}…`}>
                        {chip}
                      </span>
                    );
                  })}
                </div>
              </section>
            ))}

            {/* dynamic agents — not selectable; spawn at runtime */}
            <section aria-label="Dynamic agents — runtime spawn">
              <h4 className="mb-1.5 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-fuchsia-400/90">
                <Zap className="h-3 w-3" aria-hidden />
                Dynamic — dormant until triggered at runtime
              </h4>
              <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                {DYNAMIC_AGENTS_WIZARD.map((agent) => (
                  <div
                    key={agent.key}
                    title={agent.spawnOnDesc ?? undefined}
                    className="flex items-center gap-2 rounded-md border border-dashed border-fuchsia-500/25 bg-fuchsia-500/[0.03] px-2.5 py-1.5"
                  >
                    <Zap className="h-3 w-3 shrink-0 text-fuchsia-400/80" aria-hidden />
                    <span className="min-w-0 flex-1 truncate text-[11px] font-medium text-zinc-300">
                      {agent.name}
                    </span>
                    <span className="hidden shrink-0 truncate font-mono text-[9px] text-fuchsia-400/70 sm:inline sm:max-w-[45%]">
                      {agent.spawnOnDesc}
                    </span>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                Dynamic agents sit dormant in every plan. They join mid-scan the moment their runtime
                trigger fires (e.g. SSRF reaching an internal network, or ≥2 findings from distinct
                agents on the board) — NodeZero-style runtime planning, not a fixed pipeline.
              </p>
            </section>

            {tier === "safe" && (
              <p className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-400/90">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
                Safe tier restricts the plan to the 8 read-only agents. Switch to
                standard or aggressive to include data-touching classes.
              </p>
            )}
          </motion.div>
        )}

        <DialogFooter className="flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          {step === 1 ? (
            <>
              <span className="order-2 font-mono text-[10px] text-zinc-600 sm:order-1">
                {profile} · {tier} tier
              </span>
              <div className="order-1 flex gap-2 sm:order-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => onOpenChange(false)}
                >
                  Cancel
                </Button>
                <Button type="button" size="sm" className="gap-1.5" onClick={goToStep2}>
                  Next
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden />
                </Button>
              </div>
            </>
          ) : (
            <>
              <span className="order-2 max-w-full truncate font-mono text-[11px] text-muted-foreground sm:order-1">
                {summary}
              </span>
              <div className="order-1 flex gap-2 sm:order-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setStep(1)}
                  disabled={launching}
                >
                  Back
                </Button>
                <Button
                  type="button"
                  size="sm"
                  className="gap-1.5"
                  disabled={launching || selected.length === 0}
                  onClick={() => void launch()}
                >
                  {launching ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                      Dispatching…
                    </>
                  ) : (
                    <>
                      <Radar className="h-3.5 w-3.5" aria-hidden />
                      Launch Scan
                    </>
                  )}
                </Button>
              </div>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
