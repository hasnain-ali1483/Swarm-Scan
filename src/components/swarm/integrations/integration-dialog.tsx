"use client";

// ─── Connector dialog — why / agent benefit / mistakes→guardrails / config /
//──── test / dispatch (approval-gated) / sync / activity audit trail ──────────
// Parent remounts this component (key={session}) on every open, so useState
// hydration from `integration` is safe; the `integration` prop itself stays
// live (re-derived from the query cache), so guardrails/stats update in place.

import { useState, type ReactNode } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Bot,
  CheckCircle2,
  Download,
  Eye,
  EyeOff,
  Loader2,
  PlugZap,
  Power,
  RefreshCw,
  Send,
  Settings2,
  ShieldCheck,
  TriangleAlert,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { motion } from "framer-motion";
import { INTEGRATION_CATEGORY_LABELS } from "@/lib/swarm/integrations-catalog";
import { SEVERITY_STYLES, cn, formatNumber, timeAgo, truncateMiddle } from "@/lib/swarm/format";
import type {
  IntegrationActivityAction,
  IntegrationAuth,
  IntegrationDispatchResponse,
  IntegrationGuardrails,
  IntegrationItem,
  IntegrationSyncResponse,
  IntegrationTestResponse,
  Severity,
} from "@/lib/swarm/types";
import { CONN_STATE_META } from "./conn-state";
import { useIntegrationActivity, useIntegrationMutations } from "./use-integrations";
import { humanizeKey, metaFor } from "./integration-meta";

const AUTH_LABELS: Record<IntegrationAuth, string> = {
  "api-key": "API key",
  oauth2: "OAuth2",
  token: "Token",
  webhook: "Webhook",
  basic: "Basic auth",
  native: "Native",
  none: "No auth",
};

const ACTIVITY_META: Record<
  IntegrationActivityAction,
  { icon: LucideIcon; className: string }
> = {
  test: { icon: PlugZap, className: "text-emerald-400" },
  dispatch: { icon: Send, className: "text-amber-400" },
  sync: { icon: RefreshCw, className: "text-teal-400" },
  toggle: { icon: Power, className: "text-zinc-400" },
  config: { icon: Settings2, className: "text-zinc-400" },
};

const MIN_SEVERITY_OPTIONS: { value: Severity; label: string }[] = [
  { value: "critical", label: "Critical +" },
  { value: "high", label: "High +" },
  { value: "medium", label: "Medium +" },
  { value: "low", label: "Low +" },
];

/** Guardrail flags → human chips (order matches the IntegrationGuardrails type). */
function guardrailChips(g: IntegrationGuardrails): { label: string; title: string }[] {
  const chips: { label: string; title: string }[] = [];
  if (g.rateLimitPerMin)
    chips.push({
      label: `rate-limited ${g.rateLimitPerMin}/min`,
      title: `Dispatch and sync calls are throttled server-side — the API answers 429 beyond ${g.rateLimitPerMin} calls/min`,
    });
  if (g.requiresApproval)
    chips.push({
      label: "analyst approval required",
      title: "Dispatch answers 403 until an analyst explicitly approves the run",
    });
  if (g.scopeEnforced)
    chips.push({
      label: "scope rules enforced",
      title: "Finding targets must pass the active scope rules before anything leaves the plane",
    });
  if (g.dedupeByEvidence)
    chips.push({
      label: "dedupe by evidence hash",
      title: "Findings whose evidence hash already shipped to this connector are skipped",
    });
  if (g.pinnedVersion)
    chips.push({
      label: "immutable version pin",
      title: `References are pinned to ${g.pinnedVersion} — never latest or main`,
    });
  if (g.dataMinimization)
    chips.push({
      label: "payload minimization",
      title: "Payloads are redacted and minimized before leaving the control plane",
    });
  if (g.readOnly)
    chips.push({
      label: "read-only access",
      title: "The agent gets read-only access — no write operations are exposed",
    });
  return chips;
}

function SectionHeading({ id, children }: { id: string; children: ReactNode }) {
  return (
    <h4
      id={id}
      className="text-[10px] font-medium uppercase tracking-widest text-zinc-500"
    >
      {children}
    </h4>
  );
}

export function IntegrationDialog({
  integration,
  open,
  onOpenChange,
}: {
  integration: IntegrationItem | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { saveConfig, connect, test, dispatch, sync, toggle } = useIntegrationMutations();
  const { data: activityData, isLoading: activityLoading } = useIntegrationActivity(
    integration?.id ?? null
  );

  // Hydrated once per open (parent remounts via key) — see file header.
  const [values, setValues] = useState<Record<string, string>>({ ...integration?.config });
  const [shownSecrets, setShownSecrets] = useState<Record<string, boolean>>({});
  const [testResult, setTestResult] = useState<IntegrationTestResponse | null>(null);
  const [dispatchResult, setDispatchResult] = useState<IntegrationDispatchResponse | null>(null);
  const [syncResult, setSyncResult] = useState<IntegrationSyncResponse | null>(null);
  const [minSeverity, setMinSeverity] = useState<string>("all");
  const [approveOpen, setApproveOpen] = useState(false);

  if (!integration) return null;

  const meta = metaFor(integration.key);
  const Icon = meta.icon;
  const outbound = integration.direction === "outbound";
  const chips = guardrailChips(integration.guardrails);
  const events = activityData?.events ?? [];
  const state = CONN_STATE_META[integration.connState];
  const StateIcon = state.icon;
  const live = integration.connState === "connected";

  const dirty = integration.fields.some(
    (f) => (values[f.key] ?? "") !== (integration.config[f.key] ?? "")
  );

  const anyPending =
    saveConfig.isPending || connect.isPending || test.isPending || dispatch.isPending || sync.isPending;

  /** Non-secrets always ship (so clearing works); secrets ship only when (re)typed. */
  const buildSavePayload = (): Record<string, string> => {
    const payload: Record<string, string> = {};
    for (const field of integration.fields) {
      const value = values[field.key] ?? "";
      if (field.secret) {
        if (value.trim() !== "") payload[field.key] = value; // blank + stored → keeps stored
      } else {
        payload[field.key] = value;
      }
    }
    return payload;
  };

  const handleSave = () => {
    saveConfig.mutate(
      { id: integration.id, config: buildSavePayload() },
      {
        onSuccess: (saved) => {
          // Re-hydrate the form from the stored item — secrets redact back to ""
          // so the "stored" placeholder returns and the form reads clean.
          setValues({ ...saved.integration.config });
          // A config change cleared the server-side verification — drop the
          // stale test panel so the banner is the single source of truth.
          if (saved.autoDisabled) setTestResult(null);
        },
      }
    );
  };

  const handleTest = () => {
    setTestResult(null);
    test.mutate({ id: integration.id }, { onSuccess: (res) => setTestResult(res) });
  };

  /** Verify & Connect — one chained server flow: save → test → enable-on-pass. */
  const handleConnect = () => {
    setTestResult(null);
    setDispatchResult(null);
    setSyncResult(null);
    connect.mutate(
      { id: integration.id, config: buildSavePayload() },
      {
        onSuccess: (res) => {
          setTestResult(res.test);
          setValues({ ...res.integration.config });
        },
      }
    );
  };

  const handleDisconnect = () => {
    toggle.mutate({ id: integration.id, enabled: false });
  };

  const runDispatch = (approve: boolean) => {
    dispatch.mutate(
      {
        id: integration.id,
        payload: {
          approve: approve || undefined,
          minSeverity: minSeverity === "all" ? undefined : (minSeverity as Severity),
        },
      },
      { onSuccess: (res) => setDispatchResult(res) }
    );
  };

  const handleSync = () => {
    setSyncResult(null);
    sync.mutate({ id: integration.id }, { onSuccess: (res) => setSyncResult(res) });
  };

  const fieldId = (key: string) => `cfg-${integration.id}-${key}`;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] gap-5 overflow-y-auto bg-zinc-950/95 swarm-scroll sm:max-w-2xl">
        <DialogHeader>
          <div className="flex items-center gap-3 pr-6">
            <span
              className={cn(
                "flex h-10 w-10 shrink-0 items-center justify-center rounded-md border",
                meta.tint
              )}
              aria-hidden
            >
              <Icon className="h-5 w-5" />
            </span>
            <div className="min-w-0">
              <DialogTitle className="tracking-tight">{integration.name}</DialogTitle>
              <DialogDescription className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px]">
                <span className="text-zinc-400">
                  {INTEGRATION_CATEGORY_LABELS[integration.category] ?? integration.category}
                </span>
                <span aria-hidden className="text-zinc-700">·</span>
                <Badge
                  variant="outline"
                  className="border-zinc-700/70 bg-zinc-900/40 px-1.5 text-[10px] text-zinc-400"
                >
                  {AUTH_LABELS[integration.auth] ?? integration.auth}
                </Badge>
                <Badge
                  variant="outline"
                  className={cn(
                    "gap-1 px-1.5 text-[10px]",
                    outbound
                      ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                      : "border-teal-500/30 bg-teal-500/10 text-teal-400"
                  )}
                >
                  {outbound ? (
                    <Send className="h-2.5 w-2.5" aria-hidden />
                  ) : (
                    <Download className="h-2.5 w-2.5" aria-hidden />
                  )}
                  {outbound ? "dispatches findings" : "enriches context"}
                </Badge>
                <span aria-hidden className="font-mono text-[10px] text-zinc-600">
                  {integration.key}
                </span>
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        {/* Why connect */}
        <section aria-labelledby={`intg-why-${integration.id}`}>
          <SectionHeading id={`intg-why-${integration.id}`}>Why connect</SectionHeading>
          <p className="mt-2 text-sm leading-relaxed text-zinc-300">
            {integration.description}
          </p>
        </section>

        {/* How it helps the agent */}
        <section aria-labelledby={`intg-agent-${integration.id}`}>
          <SectionHeading id={`intg-agent-${integration.id}`}>How it helps the agent</SectionHeading>
          <div className="mt-2 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
            <div className="flex items-start gap-2.5">
              <span
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                aria-hidden
              >
                <Bot className="h-3.5 w-3.5" />
              </span>
              <p className="text-xs leading-relaxed text-emerald-100/90">
                {integration.agentBenefit}
              </p>
            </div>
          </div>
        </section>

        {/* Common mistakes → guardrails */}
        <section aria-labelledby={`intg-cautions-${integration.id}`}>
          <SectionHeading id={`intg-cautions-${integration.id}`}>
            Common mistakes → guardrails
          </SectionHeading>
          <div className="mt-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
            <ul className="space-y-1.5">
              {integration.cautions.map((caution) => (
                <li
                  key={caution}
                  className="flex items-start gap-2 text-xs leading-relaxed text-zinc-300"
                >
                  <TriangleAlert
                    className="mt-0.5 h-3 w-3 shrink-0 text-amber-400"
                    aria-hidden
                  />
                  {caution}
                </li>
              ))}
            </ul>
            {chips.length > 0 && (
              <TooltipProvider delayDuration={150}>
                <div className="mt-3 flex flex-wrap gap-1.5 border-t border-amber-500/15 pt-2.5">
                  {chips.map((chip) => (
                    <Tooltip key={chip.label}>
                      <TooltipTrigger asChild>
                        <span
                          tabIndex={0}
                          className="inline-flex cursor-help items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                        >
                          <ShieldCheck className="h-2.5 w-2.5" aria-hidden />
                          {chip.label}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent
                        side="top"
                        className="max-w-64 border-zinc-800 bg-zinc-950/95 text-[11px] leading-4 text-zinc-300"
                      >
                        {chip.title}
                      </TooltipContent>
                    </Tooltip>
                  ))}
                </div>
              </TooltipProvider>
            )}
          </div>
        </section>

        {/* Connection */}
        <section aria-labelledby={`intg-config-${integration.id}`}>
          <div className="flex items-center justify-between gap-2">
            <SectionHeading id={`intg-config-${integration.id}`}>Connection</SectionHeading>
            {dirty && (
              <Badge
                variant="outline"
                className="border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-400"
              >
                unsaved changes
              </Badge>
            )}
          </div>

          {/* Truthful status banner — server-derived connState, never a guess */}
          <div
            className={cn(
              "mt-2 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border p-2.5",
              state.chip
            )}
            role="status"
            aria-live="polite"
          >
            <span className="flex items-center gap-1.5 font-mono text-[11px] font-medium uppercase tracking-wider">
              <StateIcon className="h-3.5 w-3.5" aria-hidden />
              {state.label}
            </span>
            <span className="min-w-0 flex-1 text-[11px] leading-4 opacity-80">
              {state.explanation}
              {integration.lastTest && (
                <>{" "}Last test {integration.lastTest.ok ? "passed" : "failed"}{" "}
                  {timeAgo(integration.lastTest.at)}
                  {integration.lastTest.ok && ` · ${integration.lastTest.latencyMs}ms`}.</>
              )}
            </span>
            {live && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleDisconnect}
                disabled={anyPending}
                className="h-7 border-zinc-700 px-2.5 text-[11px] text-zinc-300 hover:border-red-500/40 hover:text-red-300"
                aria-label={`Disconnect ${integration.name}`}
              >
                <Power className="h-3 w-3" aria-hidden />
                Disconnect
              </Button>
            )}
          </div>

          {integration.fields.length === 0 ? (
            <p className="mt-2 rounded-md border border-dashed border-zinc-800 p-3 text-center text-xs text-zinc-500">
              This connector has no configurable fields.
            </p>
          ) : (
            <div className="mt-2 space-y-3">
              {integration.fields.map((field) => {
                const label = field.label ?? humanizeKey(field.key);
                const value = values[field.key] ?? "";
                const stored = integration.configSet.includes(field.key);
                const shown = !!shownSecrets[field.key];
                const secretPlaceholder =
                  field.secret && stored && value === ""
                    ? "•••• stored — leave blank to keep"
                    : (field.placeholder ?? "");
                return (
                  <div key={field.key} className="space-y-1.5">
                    <Label htmlFor={fieldId(field.key)} className="text-xs text-zinc-300">
                      {label}
                      {field.required && (
                        <span className="ml-0.5 text-red-400" aria-hidden>
                          *
                        </span>
                      )}
                    </Label>
                    <div className="relative">
                      <Input
                        id={fieldId(field.key)}
                        type={field.secret && !shown ? "password" : "text"}
                        value={value}
                        onChange={(e) =>
                          setValues((prev) => ({ ...prev, [field.key]: e.target.value }))
                        }
                        placeholder={secretPlaceholder}
                        className={cn("font-mono text-xs", field.secret && "pr-10")}
                        spellCheck={false}
                        autoComplete="off"
                        aria-label={`${label} for ${integration.name}`}
                      />
                      {field.secret && (
                        <button
                          type="button"
                          onClick={() =>
                            setShownSecrets((prev) => ({ ...prev, [field.key]: !prev[field.key] }))
                          }
                          className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-zinc-500 transition-colors hover:text-zinc-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                          aria-label={shown ? `Hide ${label}` : `Show ${label}`}
                          aria-pressed={shown}
                        >
                          {shown ? (
                            <EyeOff className="h-3.5 w-3.5" aria-hidden />
                          ) : (
                            <Eye className="h-3.5 w-3.5" aria-hidden />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}

              <div className="flex flex-wrap items-center gap-2 pt-1">
                {!live && (
                  <Button
                    size="sm"
                    onClick={handleConnect}
                    disabled={anyPending}
                    className="h-8 gap-1.5 text-xs"
                    aria-label={`Verify and connect ${integration.name}`}
                  >
                    {connect.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                    ) : (
                      <PlugZap className="h-3.5 w-3.5" aria-hidden />
                    )}
                    Verify &amp; connect
                  </Button>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleTest}
                  disabled={test.isPending || anyPending}
                  className="h-8 gap-1.5 text-xs"
                  aria-label={`Test connection for ${integration.name}`}
                >
                  {test.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                  ) : (
                    <PlugZap className="h-3.5 w-3.5" aria-hidden />
                  )}
                  {live ? "Re-test" : "Test only"}
                </Button>
                {!live && dirty && (
                  <span className="text-[10px] text-amber-400/80">
                    saves the form, then verifies — enabling only on pass
                  </span>
                )}
                {!live && !dirty && integration.connState !== "not_configured" && (
                  <span className="text-[10px] text-zinc-500">
                    tests the stored config — enabling only on pass
                  </span>
                )}
              </div>

              {testResult && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className={cn(
                    "rounded-lg border p-3",
                    testResult.ok
                      ? "border-emerald-500/25 bg-emerald-500/5"
                      : "border-red-500/25 bg-red-500/5"
                  )}
                  role="status"
                >
                  <div className="flex items-start gap-2">
                    {testResult.ok ? (
                      <CheckCircle2
                        className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400"
                        aria-hidden
                      />
                    ) : (
                      <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" aria-hidden />
                    )}
                    <div className="min-w-0">
                      <p
                        className={cn(
                          "font-mono text-xs leading-4",
                          testResult.ok ? "text-emerald-300" : "text-red-300"
                        )}
                      >
                        {testResult.ok
                          ? `Verified — ${testResult.latencyMs}ms · ${testResult.detail}`
                          : "Connection failed"}
                      </p>
                      {!testResult.ok && testResult.issues.length > 0 && (
                        <ul className="mt-1.5 space-y-1">
                          {testResult.issues.map((issue) => (
                            <li key={issue} className="text-[11px] leading-4 text-red-200/80">
                              · {issue}
                            </li>
                          ))}
                        </ul>
                      )}
                      {testResult.ok && (
                        <p className="mt-1 text-[11px] leading-4 text-emerald-300/70">
                          {live
                            ? "Connector enabled — dispatch and sync are live."
                            : "Passed — the switch on the card (or Verify & connect above) can now enable it."}
                        </p>
                      )}
                      <p className="mt-1 font-mono text-[10px] text-zinc-600">
                        checked {timeAgo(testResult.checkedAt)}
                      </p>
                    </div>
                  </div>
                </motion.div>
              )}
            </div>
          )}
        </section>

        {/* Actions — dispatch (outbound) / sync (inbound) */}
        <section aria-labelledby={`intg-actions-${integration.id}`}>
          <SectionHeading id={`intg-actions-${integration.id}`}>Actions</SectionHeading>
          {!live ? (
            <p className="mt-2 rounded-md border border-dashed border-zinc-800 px-3 py-2.5 text-center text-[11px] text-zinc-500">
              {integration.connState === "not_configured"
                ? "Configure the connection fields, then verify — actions unlock on a passing test."
                : integration.connState === "failed"
                  ? "The last connection test failed — fix the issues and re-verify to unlock actions."
                  : integration.connState === "unverified"
                    ? "Run Verify & connect above — actions unlock once the test passes."
                    : "Connector verified but switched off — flip the card switch on to unlock actions."}
            </p>
          ) : outbound ? (
            <div className="mt-2 space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex items-center gap-2">
                  <Label
                    htmlFor={`min-sev-${integration.id}`}
                    className="text-xs text-zinc-400"
                  >
                    Min severity
                  </Label>
                  <Select value={minSeverity} onValueChange={setMinSeverity}>
                    <SelectTrigger
                      id={`min-sev-${integration.id}`}
                      className="h-8 w-36 text-xs"
                      aria-label="Minimum severity for dispatch"
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-950/95">
                      <SelectItem value="all">All severities</SelectItem>
                      {MIN_SEVERITY_OPTIONS.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <Button
                  size="sm"
                  onClick={() =>
                    integration.guardrails.requiresApproval
                      ? setApproveOpen(true)
                      : runDispatch(false)
                  }
                  disabled={anyPending}
                  className="h-8 gap-1.5 text-xs"
                  aria-label={`Dispatch confirmed findings to ${integration.name}`}
                >
                  {dispatch.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                  ) : (
                    <Send className="h-3.5 w-3.5" aria-hidden />
                  )}
                  Dispatch confirmed findings
                </Button>
              </div>

              {dispatchResult && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3"
                  role="status"
                >
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge
                      variant="outline"
                      className="border-emerald-500/30 bg-emerald-500/10 px-1.5 font-mono text-[10px] text-emerald-400"
                    >
                      dispatched {dispatchResult.dispatched}
                    </Badge>
                    {dispatchResult.skippedDuplicates > 0 && (
                      <Badge
                        variant="outline"
                        className="border-amber-500/30 bg-amber-500/10 px-1.5 font-mono text-[10px] text-amber-400"
                      >
                        skipped duplicates {dispatchResult.skippedDuplicates}
                      </Badge>
                    )}
                    {dispatchResult.skippedOutOfScope > 0 && (
                      <Badge
                        variant="outline"
                        className="border-zinc-700 bg-zinc-900 px-1.5 font-mono text-[10px] text-zinc-400"
                      >
                        out of scope {dispatchResult.skippedOutOfScope}
                      </Badge>
                    )}
                  </div>
                  {dispatchResult.items.length > 0 ? (
                    <ul className="mt-2 max-h-40 space-y-1.5 overflow-y-auto pr-1 swarm-scroll">
                      {dispatchResult.items.map((item) => (
                        <li
                          key={item.ref}
                          className="flex items-center gap-2 rounded-md border border-zinc-800/80 bg-zinc-950/60 px-2 py-1.5"
                        >
                          <span className="shrink-0 font-mono text-[11px] text-emerald-400">
                            {item.ref}
                          </span>
                          <Badge
                            variant="outline"
                            className={cn(
                              "shrink-0 px-1.5 text-[10px]",
                              SEVERITY_STYLES[item.severity].badge
                            )}
                          >
                            {SEVERITY_STYLES[item.severity].label}
                          </Badge>
                          <span className="min-w-0 flex-1 truncate text-xs text-zinc-300">
                            {item.title}
                          </span>
                          <span
                            className="shrink-0 font-mono text-[10px] text-zinc-600"
                            title={item.target}
                          >
                            {truncateMiddle(item.target, 24)}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-2 text-[11px] leading-4 text-zinc-500">
                      No new confirmed findings — everything matching is already dispatched
                      (dedupe by evidence hash) or filtered.
                    </p>
                  )}
                </motion.div>
              )}
            </div>
          ) : (
            <div className="mt-2 space-y-3">
              <Button
                size="sm"
                onClick={handleSync}
                disabled={anyPending}
                className="h-8 gap-1.5 text-xs"
                aria-label={`Sync context from ${integration.name}`}
              >
                {sync.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                )}
                Sync now
              </Button>
              {syncResult && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3"
                  role="status"
                >
                  <div className="grid grid-cols-2 gap-2">
                    {syncResult.metrics.map((metric) => (
                      <div
                        key={metric.label}
                        className="rounded-md border border-zinc-800/80 bg-zinc-950/60 px-2.5 py-2"
                      >
                        <p className="text-[10px] uppercase tracking-wider text-zinc-500">
                          {metric.label}
                        </p>
                        <p className="mt-0.5 font-mono text-sm tabular-nums text-zinc-200">
                          {formatNumber(metric.value)}
                          {metric.unit && (
                            <span className="ml-0.5 text-[10px] text-zinc-500">
                              {metric.unit}
                            </span>
                          )}
                        </p>
                      </div>
                    ))}
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-zinc-400">
                    {syncResult.summary}
                  </p>
                  <p className="mt-1 font-mono text-[10px] text-zinc-600">
                    synced {timeAgo(syncResult.syncedAt)}
                  </p>
                </motion.div>
              )}
            </div>
          )}
        </section>

        {/* Recent activity */}
        <section aria-labelledby={`intg-activity-${integration.id}`}>
          <SectionHeading id={`intg-activity-${integration.id}`}>Recent activity</SectionHeading>
          <div className="mt-2 rounded-lg border border-zinc-800 bg-zinc-900/30">
            {activityLoading ? (
              <div className="space-y-2 p-3">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-4 w-1/2" />
              </div>
            ) : events.length === 0 ? (
              <p className="p-3 text-[11px] text-zinc-500">
                No activity yet — test or dispatch to see the audit trail.
              </p>
            ) : (
              <ul
                className="max-h-40 divide-y divide-zinc-800/60 overflow-y-auto swarm-scroll"
                role="log"
                aria-label={`Recent activity for ${integration.name}`}
              >
                {events.map((event) => {
                  const actionMeta = ACTIVITY_META[event.action] ?? ACTIVITY_META.config;
                  const ActionIcon = actionMeta.icon;
                  return (
                    <li key={event.id} className="flex items-center gap-2.5 px-3 py-2">
                      <ActionIcon
                        className={cn("h-3 w-3 shrink-0", actionMeta.className)}
                        aria-hidden
                      />
                      <span className="min-w-0 flex-1 truncate text-xs text-zinc-300">
                        {event.message}
                      </span>
                      <span className="shrink-0 font-mono text-[10px] text-zinc-600">
                        {timeAgo(event.createdAt)}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </section>

        <DialogFooter className="flex-col gap-2 border-t border-zinc-800/80 pt-4 sm:flex-row sm:items-center sm:justify-between">
          <span className="order-last font-mono text-[10px] text-zinc-600 sm:order-first">
            {integration.key} · {integration.configSet.length} stored value
            {integration.configSet.length === 1 ? "" : "s"}
            {live && dirty && (
              <span className="ml-2 text-amber-400/90">
                saving disconnects until re-verified
              </span>
            )}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={anyPending}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={anyPending || integration.fields.length === 0}
              className="gap-2"
              aria-label={`Save configuration for ${integration.name}`}
            >
              {saveConfig.isPending && (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              )}
              Save configuration
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>

      {/* SOAR approval gate — guardrails.requiresApproval connectors only */}
      <AlertDialog open={approveOpen} onOpenChange={setApproveOpen}>
        <AlertDialogContent className="border-zinc-800 bg-zinc-950/95 sm:max-w-md">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <TriangleAlert className="h-4 w-4 text-amber-400" aria-hidden />
              Approve SOAR dispatch
            </AlertDialogTitle>
            <AlertDialogDescription>
              {integration.name} playbooks execute real response actions. This dispatch sends
              confirmed findings to the allowlisted playbooks — the action is audited and
              rate-limited, but cannot be rolled back automatically.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={dispatch.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => runDispatch(true)}
              disabled={dispatch.isPending}
              className="gap-1.5"
            >
              {dispatch.isPending && (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              )}
              Approve &amp; dispatch
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Dialog>
  );
}
