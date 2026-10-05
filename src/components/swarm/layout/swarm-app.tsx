"use client";

// ─── SwarmScan application shell ─────────────────────────────────────────────
// Sidebar navigation + header (engine bus status, global kill switch) +
// view router + sticky footer. Views themselves are implemented in
// src/components/swarm/views/* by the frontend tasks.

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Bot,
  ClipboardCheck,
  Crosshair,
  FileJson,
  Fingerprint,
  GitBranch,
  LayoutDashboard,
  Lock,
  Network,
  Plug,
  Radar,
  ScrollText,
  ShieldCheck,
  Siren,
  Target,
  Waypoints,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
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
import { useToast } from "@/hooks/use-toast";
import { SwarmProviders, useEngineSocket } from "@/components/swarm/providers";
import { ActingRolePill } from "@/components/swarm/access/role-simulator";
import { DownloadProjectButton } from "@/components/swarm/layout/download-project-button";
import { roleCan } from "@/lib/swarm/access-roles";
import { useSwarmUi, type SwarmView } from "@/lib/swarm/ui-store";
import { api, type EngineStats } from "@/lib/swarm/types";
import { cn } from "@/lib/utils";

const NAV_ITEMS: { key: SwarmView; label: string; icon: typeof Radar; hint: string }[] = [
  { key: "overview", label: "Overview", icon: LayoutDashboard, hint: "Live SOC dashboard" },
  { key: "targets", label: "Targets", icon: Crosshair, hint: "Authorized engagement targets" },
  { key: "scans", label: "Scans", icon: Radar, hint: "Scan plans & execution" },
  { key: "findings", label: "Findings", icon: Siren, hint: "Bayesian evidence" },
  { key: "attack-graph", label: "Attack Graph", icon: Network, hint: "Correlated chains" },
  { key: "graph", label: "Graph Explorer", icon: Waypoints, hint: "GraphQL finding graph" },
  { key: "ledger", label: "Evidence Ledger", icon: ScrollText, hint: "WORM audit trail" },
  { key: "agents", label: "Agents", icon: Bot, hint: "FSM agent registry" },
  { key: "benchmark", label: "Benchmark", icon: Target, hint: "500-case FN regression" },
  { key: "policies", label: "Policies", icon: ShieldCheck, hint: "OPA/Rego + scope firewall" },
  { key: "reports", label: "Reports", icon: FileJson, hint: "Executive / SARIF" },
  { key: "compliance", label: "Compliance", icon: ClipboardCheck, hint: "SOC 2 packs · scheduler" },
  { key: "integrations", label: "Integrations", icon: Plug, hint: "Ticketing, CI/CD, SIEM" },
  { key: "access", label: "Access Control", icon: Fingerprint, hint: "RBAC · SSO · sessions · keys" },
];

const VIEW_TITLES: Record<SwarmView, { title: string; sub: string }> = {
  overview: { title: "Operations Overview", sub: "Live control-plane telemetry" },
  targets: { title: "Targets", sub: "Registered engagement targets — authorize before scanning" },
  scans: { title: "Scans", sub: "DAG scan plans and execution plane" },
  findings: { title: "Findings", sub: "Bayesian confidence model" },
  "attack-graph": { title: "Attack Graph", sub: "CorrelatorAgent exploitation paths" },
  graph: { title: "Graph Explorer", sub: "GraphQL finding graph — query the output plane" },
  ledger: { title: "Evidence Ledger", sub: "Hash-chained WORM audit trail" },
  agents: { title: "Agent Registry", sub: "34 FSM agents — classic, unorthodox & dynamic-spawn" },
  benchmark: { title: "Benchmark Corpus", sub: "500-case FN regression — the scanner's CI" },
  policies: { title: "Policy Engine", sub: "OPA/Rego governance + scope firewall" },
  reports: { title: "Reports", sub: "Executive, technical, SARIF 2.1" },
  compliance: { title: "Compliance", sub: "SOC 2 evidence packs from the WORM ledger · export scheduler" },
  integrations: { title: "Integrations", sub: "Ticketing, CI/CD, SIEM, secrets" },
  access: { title: "Access Control", sub: "RBAC roles · SSO (SAML/OIDC/SCIM) · sessions · API keys" },
};

function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5 select-none">
      <div className="relative flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 border border-primary/30">
        <Zap className="h-4.5 w-4.5 text-primary" aria-hidden />
        <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-primary swarm-pulse text-primary" />
      </div>
      {!compact && (
        <div className="leading-tight">
          <div className="font-semibold tracking-tight text-[15px]">
            Swarm<span className="text-primary">Scan</span>
          </div>
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
            Autonomous Scanner
          </div>
        </div>
      )}
    </div>
  );
}

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const view = useSwarmUi((s) => s.view);
  const setView = useSwarmUi((s) => s.setView);
  return (
    <nav aria-label="Primary" className="flex flex-col gap-1 px-2">
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon;
        const active = view === item.key;
        return (
          <button
            key={item.key}
            onClick={() => {
              setView(item.key);
              onNavigate?.();
            }}
            aria-current={active ? "page" : undefined}
            className={cn(
              "group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors text-left",
              active
                ? "bg-primary/12 text-primary-foreground bg-accent"
                : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
            )}
          >
            <Icon
              className={cn(
                "h-4 w-4 shrink-0",
                active ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
              )}
              aria-hidden
            />
            <span className="flex-1 font-medium">{item.label}</span>
            {active && <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden />}
          </button>
        );
      })}
    </nav>
  );
}

function BusStatus() {
  const { connected } = useEngineSocket();
  return (
    <div className="px-4 py-3 rounded-md border bg-card/50">
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">Event bus</span>
        <span
          className={cn(
            "flex items-center gap-1.5 font-medium",
            connected ? "text-primary" : "text-destructive"
          )}
        >
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              connected ? "bg-primary swarm-pulse" : "bg-destructive"
            )}
            aria-hidden
          />
          {connected ? "NATS ▸ live" : "offline"}
        </span>
      </div>
      <div className="mt-1.5 flex items-center justify-between text-xs">
        <span className="text-muted-foreground">Engine</span>
        <span className="font-mono text-[10px] text-muted-foreground">:3003</span>
      </div>
    </div>
  );
}

function KillSwitch() {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [killing, setKilling] = useState(false);
  const actingRole = useSwarmUi((s) => s.actingRole);
  const canEngage = roleCan(actingRole, "killswitch:engage");

  const killAll = async () => {
    setKilling(true);
    try {
      const res = await api<{ latencyMs: number; message: string }>(
        "/api/engine/kill",
        { method: "POST" }
      );
      toast({
        title: "GLOBAL KILL SWITCH ENGAGED",
        description: `${res.message} — propagated in ${res.latencyMs}ms. All worker sandboxes received SIGKILL.`,
        variant: "destructive",
      });
      await queryClient.invalidateQueries();
    } catch (err) {
      toast({
        title: "Kill switch failed",
        description: err instanceof Error ? err.message : "Engine unreachable",
        variant: "destructive",
      });
    } finally {
      setKilling(false);
      setOpen(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button
          variant="destructive"
          size="sm"
          className="gap-2 font-semibold shadow-[inset_0_1px_0_rgba(255,255,255,0.12)] transition-all hover:brightness-110 active:scale-[0.97] active:brightness-95 disabled:opacity-50"
          aria-label={
            canEngage
              ? "Engage global kill switch"
              : `Kill switch locked — ${actingRole} lacks killswitch:engage (change in Access Control)`
          }
          disabled={!canEngage}
          title={
            canEngage
              ? undefined
              : `${actingRole} role cannot engage the kill switch — switch the acting role in Access Control`
          }
        >
          {canEngage ? <Siren className="h-4 w-4" aria-hidden /> : <Lock className="h-4 w-4" aria-hidden />}
          <span className="hidden sm:inline">Kill Switch</span>
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Engage global kill switch?</AlertDialogTitle>
          <AlertDialogDescription>
            All in-flight requests across every worker sandbox receive SIGKILL within
            500&nbsp;ms. Active scans are terminated and marked <code>killed</code>.
            Evidence collected so far is preserved in the WORM ledger.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => {
              e.preventDefault();
              void killAll();
            }}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {killing ? "Engaging…" : "Engage kill switch"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function EngineStatsPills() {
  const { stats, connected } = useEngineSocket();
  return (
    <div className="hidden md:flex items-center gap-2">
      <Badge
        variant="outline"
        className="gap-1.5 font-mono text-[11px] bg-card/60"
        title="Sustained request throughput across workers"
      >
        <Activity className="h-3 w-3 text-primary" aria-hidden />
        {stats ? `${stats.requestsPerMin.toLocaleString()} req/min` : connected ? "…" : "—"}
      </Badge>
      <Badge
        variant="outline"
        className="gap-1.5 font-mono text-[11px] bg-card/60"
        title="Active scans on the execution plane"
      >
        <Radar className="h-3 w-3 text-primary" aria-hidden />
        {stats ? `${stats.activeScans} active` : "—"}
      </Badge>
      <Badge
        variant="outline"
        className="gap-1.5 font-mono text-[11px] bg-card/60"
        title="gVisor worker sandboxes"
      >
        <Bot className="h-3 w-3 text-primary" aria-hidden />
        {stats ? `${stats.workers} workers` : "—"}
      </Badge>
    </div>
  );
}

function ShellContent() {
  const view = useSwarmUi((s) => s.view);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <div className="flex flex-1 min-h-0">
        {/* Desktop sidebar */}
        <aside className="hidden lg:flex w-60 shrink-0 flex-col border-r bg-sidebar/60 backdrop-blur-sm">
          <div className="flex h-14 items-center px-4 border-b">
            <Logo />
          </div>
          <div className="flex-1 overflow-y-auto py-3 swarm-scroll">
            <NavList />
          </div>
          <div className="p-3 border-t">
            <BusStatus />
          </div>
        </aside>

        <div className="flex-1 flex flex-col min-w-0">
          {/* Header */}
          <header className="sticky top-0 z-40 flex h-14 items-center gap-3 border-b bg-background/85 backdrop-blur px-4 lg:px-6">
            {/* Mobile nav */}
            <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon" className="lg:hidden" aria-label="Open navigation">
                  <LayoutDashboard className="h-4 w-4" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-64 p-0">
                <SheetHeader className="border-b py-4 px-4">
                  <SheetTitle asChild>
                    <div>
                      <Logo />
                    </div>
                  </SheetTitle>
                </SheetHeader>
                <div className="py-3">
                  <NavList onNavigate={() => setMobileNavOpen(false)} />
                </div>
                <div className="p-3 border-t mt-auto absolute bottom-0 left-0 right-0">
                  <BusStatus />
                </div>
              </SheetContent>
            </Sheet>

            <div className="lg:hidden">
              <Logo compact />
            </div>

            <div className="hidden lg:block min-w-0">
              <h1 className="text-sm font-semibold leading-none truncate">
                {VIEW_TITLES[view].title}
              </h1>
              <p className="text-[11px] text-muted-foreground mt-1 truncate">
                {VIEW_TITLES[view].sub}
              </p>
            </div>

            <div className="ml-auto flex items-center gap-2 sm:gap-3">
              <EngineStatsPills />
              <Separator orientation="vertical" className="hidden md:block h-6" />
              <ActingRolePill />
              <Separator orientation="vertical" className="hidden md:block h-6" />
              <KillSwitch />
            </div>
          </header>

          {/* Routed view */}
          <main className="flex-1 min-w-0">
            <ViewRouter view={view} />
          </main>

          {/* Sticky footer */}
          <footer className="mt-auto border-t bg-background/85 backdrop-blur">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-1.5 px-4 lg:px-6 py-3 text-[11px] text-muted-foreground">
              <div className="flex items-center gap-2">
                <GitBranch className="h-3 w-3" aria-hidden />
                <span className="font-mono">swarmscan v0.9.2-rc</span>
                <span aria-hidden>·</span>
                <span>Deterministic plans · WORM ledger active</span>
              </div>
              <div className="flex items-center gap-2">
                <DownloadProjectButton />
                <span aria-hidden className="text-zinc-800">·</span>
                <span>SLO: FP &lt; 2% · kill &lt; 500 ms · reproducible 100%</span>
                <span aria-hidden>·</span>
                <span>© 2025 SwarmScan Labs</span>
              </div>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}

// View router — placeholders are replaced by frontend task agents.
import { OverviewView } from "@/components/swarm/views/overview-view";
import { TargetsView } from "@/components/swarm/views/targets-view";
import { ScansView } from "@/components/swarm/views/scans-view";
import { FindingsView } from "@/components/swarm/views/findings-view";
import { AttackGraphView } from "@/components/swarm/views/attack-graph-view";
import { GraphExplorerView } from "@/components/swarm/views/graph-explorer-view";
import { LedgerView } from "@/components/swarm/views/ledger-view";
import { AgentsView } from "@/components/swarm/views/agents-view";
import { BenchmarkView } from "@/components/swarm/views/benchmark-view";
import { PoliciesView } from "@/components/swarm/views/policies-view";
import { ReportsView } from "@/components/swarm/views/reports-view";
import { ComplianceView } from "@/components/swarm/views/compliance-view";
import { IntegrationsView } from "@/components/swarm/views/integrations-view";
import { AccessView } from "@/components/swarm/views/access-view";

function ViewRouter({ view }: { view: SwarmView }) {
  switch (view) {
    case "overview":
      return <OverviewView />;
    case "targets":
      return <TargetsView />;
    case "scans":
      return <ScansView />;
    case "findings":
      return <FindingsView />;
    case "attack-graph":
      return <AttackGraphView />;
    case "graph":
      return <GraphExplorerView />;
    case "ledger":
      return <LedgerView />;
    case "agents":
      return <AgentsView />;
    case "benchmark":
      return <BenchmarkView />;
    case "policies":
      return <PoliciesView />;
    case "reports":
      return <ReportsView />;
    case "compliance":
      return <ComplianceView />;
    case "integrations":
      return <IntegrationsView />;
    case "access":
      return <AccessView />;
    default:
      return null;
  }
}

export function SwarmApp() {
  return (
    <SwarmProviders>
      <ShellContent />
    </SwarmProviders>
  );
}
