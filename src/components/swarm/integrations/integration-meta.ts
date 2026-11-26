"use client";

// ─── Integration metadata: per-connector icons, category tints, humanizer ─────
// Maps all 47 catalog keys to a specific lucide icon + its category tint.
// No blue/indigo in the SOC palette — zinc/emerald/amber/teal/orange/red/lime/green only.

import {
  AudioWaveform,
  BarChart3,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  Compass,
  Cpu,
  Crosshair,
  Database,
  DatabaseZap,
  FileStack,
  Fingerprint,
  GitBranch,
  GitMerge,
  Github,
  Globe,
  Globe2,
  Hammer,
  HardDrive,
  Headset,
  KanbanSquare,
  KeyRound,
  KeySquare,
  Layers,
  LineChart,
  ListChecks,
  Lock,
  Mail,
  MessageSquare,
  Network,
  PersonStanding,
  Play,
  Plug,
  Radio,
  Radar,
  Route,
  Satellite,
  ScanLine,
  ScanSearch,
  Search,
  SearchCode,
  Server,
  Share2,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  Shuffle,
  Siren,
  Sparkles,
  SquareCheckBig,
  Table2,
  Telescope,
  Ticket,
  UserCheck,
  Users,
  Waves,
  Workflow,
  Zap,
  type LucideIcon,
} from "lucide-react";
import type { IntegrationCategory } from "@/lib/swarm/types";

export interface IntegrationMeta {
  icon: LucideIcon;
  /** tinted icon square classes */
  tint: string;
}

// Per-category tints — consistent within a category, in-palette only.
const TINT = {
  teal: "border-teal-500/30 bg-teal-500/10 text-teal-400",
  red: "border-red-500/30 bg-red-500/10 text-red-400",
  orange: "border-orange-500/30 bg-orange-500/10 text-orange-400",
  amber: "border-amber-500/30 bg-amber-500/10 text-amber-400",
  emerald: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  lime: "border-lime-500/30 bg-lime-500/10 text-lime-400",
  green: "border-green-500/30 bg-green-500/10 text-green-400",
  zinc: "border-zinc-600/40 bg-zinc-800/60 text-zinc-300",
} as const;

/** All 47 catalog keys → evocative lucide icon (no brand icons in lucide). */
export const INTEGRATION_META: Record<string, IntegrationMeta> = {
  // recon — teal
  shodan: { icon: Satellite, tint: TINT.teal },
  censys: { icon: Network, tint: TINT.teal },
  securitytrails: { icon: Route, tint: TINT.teal },
  greynoise: { icon: AudioWaveform, tint: TINT.teal },
  urlscan: { icon: ScanSearch, tint: TINT.teal },
  // vulnerability — red
  nuclei: { icon: Bug, tint: TINT.red },
  "nuclei-templates": { icon: FileStack, tint: TINT.red },
  // threat-intel — orange
  virustotal: { icon: ShieldCheck, tint: TINT.orange },
  misp: { icon: Share2, tint: TINT.orange },
  otx: { icon: Globe2, tint: TINT.orange },
  // ticketing — amber
  jira: { icon: KanbanSquare, tint: TINT.amber },
  servicenow: { icon: Ticket, tint: TINT.amber },
  zendesk: { icon: Headset, tint: TINT.amber },
  freshservice: { icon: ClipboardList, tint: TINT.amber },
  // siem — emerald
  splunk: { icon: Search, tint: TINT.emerald },
  sentinel: { icon: Radar, tint: TINT.emerald },
  qradar: { icon: Layers, tint: TINT.emerald },
  elastic: { icon: BarChart3, tint: TINT.emerald },
  "gcp-secops": { icon: DatabaseZap, tint: TINT.emerald },
  wazuh: { icon: ShieldAlert, tint: TINT.emerald },
  // soar — lime
  "cortex-xsoar": { icon: Workflow, tint: TINT.lime },
  "splunk-soar": { icon: Bot, tint: TINT.lime },
  tines: { icon: GitMerge, tint: TINT.lime },
  swimlane: { icon: Waves, tint: TINT.lime },
  torq: { icon: Zap, tint: TINT.lime },
  shuffle: { icon: Shuffle, tint: TINT.lime },
  "cloudflare-waf": { icon: ShieldCheck, tint: TINT.lime },
  "aws-waf": { icon: ShieldHalf, tint: TINT.lime },
  // communication — green
  slack: { icon: MessageSquare, tint: TINT.green },
  teams: { icon: Users, tint: TINT.green },
  email: { icon: Mail, tint: TINT.green },
  // data — zinc
  postgresql: { icon: Database, tint: TINT.zinc },
  mysql: { icon: HardDrive, tint: TINT.zinc },
  elasticsearch: { icon: SearchCode, tint: TINT.zinc },
  // identity — emerald (in-palette only; distinct icons from SIEM)
  "entra-id": { icon: Fingerprint, tint: TINT.emerald },
  okta: { icon: KeySquare, tint: TINT.emerald },
  // mcp — teal (distinct icons from recon)
  "mcp-recon": { icon: Compass, tint: TINT.teal },
  "mcp-nuclei": { icon: Crosshair, tint: TINT.teal },
  "mcp-threat-intel": { icon: Siren, tint: TINT.teal },
  "mcp-siem": { icon: LineChart, tint: TINT.teal },
  "mcp-ticketing": { icon: SquareCheckBig, tint: TINT.teal },
  "mcp-soar": { icon: Play, tint: TINT.teal },
  "mcp-database": { icon: Table2, tint: TINT.teal },
  // ai — amber
  "llm-provider": { icon: Brain, tint: TINT.amber },
  // architecture — zinc
  "mcp-gateway": { icon: ShieldHalf, tint: TINT.zinc },
  // cicd — zinc
  github: { icon: Github, tint: TINT.zinc },
  gitlab: { icon: GitBranch, tint: TINT.zinc },
  jenkins: { icon: PersonStanding, tint: TINT.zinc },
  // secrets — amber
  vault: { icon: KeyRound, tint: TINT.amber },
};

const FALLBACK: IntegrationMeta = { icon: Plug, tint: TINT.zinc };

/** Specific icon + tint for a connector key (falls back to Plug/zinc). */
export function metaFor(key: string): IntegrationMeta {
  return INTEGRATION_META[key] ?? FALLBACK;
}

/** Category-level icon, tint and one-line description. */
export const CATEGORY_META: Record<
  IntegrationCategory,
  { icon: LucideIcon; tint: string; text: string; blurb: string }
> = {
  recon: {
    icon: Telescope,
    tint: TINT.teal,
    text: "text-teal-400",
    blurb: "External attack-surface discovery and enrichment",
  },
  vulnerability: {
    icon: ScanLine,
    tint: TINT.red,
    text: "text-red-400",
    blurb: "Template-driven scanning and exposure validation",
  },
  "threat-intel": {
    icon: Globe,
    tint: TINT.orange,
    text: "text-orange-400",
    blurb: "Indicator feeds and reputation lookups",
  },
  ticketing: {
    icon: Ticket,
    tint: TINT.amber,
    text: "text-amber-400",
    blurb: "Findings routed into owned, SLA-tracked work items",
  },
  siem: {
    icon: Radar,
    tint: TINT.emerald,
    text: "text-emerald-400",
    blurb: "Findings streamed into retention and correlation",
  },
  soar: {
    icon: ListChecks,
    tint: TINT.lime,
    text: "text-lime-400",
    blurb: "Analyst-gated automation and response playbooks",
  },
  communication: {
    icon: Radio,
    tint: TINT.green,
    text: "text-green-400",
    blurb: "Human notification channels",
  },
  data: {
    icon: Server,
    tint: TINT.zinc,
    text: "text-zinc-300",
    blurb: "Read context from internal data stores",
  },
  identity: {
    icon: UserCheck,
    tint: TINT.emerald,
    text: "text-emerald-400",
    blurb: "Directory and access context for ownership mapping",
  },
  mcp: {
    icon: Cpu,
    tint: TINT.teal,
    text: "text-teal-400",
    blurb: "Model Context Protocol tool servers for the agent",
  },
  ai: {
    icon: Sparkles,
    tint: TINT.amber,
    text: "text-amber-400",
    blurb: "LLM providers powering reasoning and triage",
  },
  architecture: {
    icon: ShieldHalf,
    tint: TINT.zinc,
    text: "text-zinc-300",
    blurb: "The policy gateway every tool call crosses",
  },
  cicd: {
    icon: Hammer,
    tint: TINT.zinc,
    text: "text-zinc-300",
    blurb: "Publish and release gates for the agent registry",
  },
  secrets: {
    icon: Lock,
    tint: TINT.amber,
    text: "text-amber-400",
    blurb: "Credential custody and rotation",
  },
};

const ACRONYMS = new Set([
  "url",
  "id",
  "jql",
  "api",
  "ci",
  "org",
  "hec",
  "ttl",
  "ssl",
  "mcp",
  "smtp",
  "dsn",
  "sla",
  "ui",
  "ids",
  "xss",
  "ssrf",
]);

/** "projectKey" / "webhook_url" → "Project key" / "Webhook URL". */
export function humanizeKey(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .trim()
    .split(/\s+/)
    .map((w) => {
      const lower = w.toLowerCase();
      if (ACRONYMS.has(lower)) return lower.toUpperCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    });
  return words.join(" ");
}
