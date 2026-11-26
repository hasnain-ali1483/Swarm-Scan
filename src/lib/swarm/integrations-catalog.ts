// ─── Integration catalog — 47 connectors across 14 categories ─────────────────
// Single source of truth for connector metadata: why it should be connected,
// how it helps the AI agent, and the common implementation mistakes which are
// turned into server-enforced guardrails (see server/integrations.ts).
//
// The DB `Integration` table stores ONLY connection state (enabled / config
// values / lastTest / lastSyncAt). This catalog is imported by both the API
// routes (merge + validation + guardrail enforcement) and the frontend
// (category grouping, icons, dialogs). Keys are stable — they match the DB.
//
// OWNED BY ORCHESTRATOR — subagents must not edit.

import type {
  IntegrationAuth,
  IntegrationCategory,
  IntegrationDirection,
  IntegrationFieldSpec,
  IntegrationGuardrails,
} from "@/lib/swarm/types";

export interface IntegrationCatalogEntry {
  key: string;
  name: string;
  category: IntegrationCategory;
  direction: IntegrationDirection;
  auth: IntegrationAuth;
  /** Why it should be connected */
  description: string;
  /** How it helps the AI agent */
  agentBenefit: string;
  /** Common implementation mistakes */
  cautions: string[];
  guardrails: IntegrationGuardrails;
  fields: IntegrationFieldSpec[];
  /** outbound reference prefix, e.g. "VULN" → VULN-1042 */
  refPrefix?: string;
}

export const INTEGRATION_CATEGORY_ORDER: IntegrationCategory[] = [
  "recon",
  "vulnerability",
  "threat-intel",
  "ticketing",
  "siem",
  "soar",
  "communication",
  "data",
  "identity",
  "mcp",
  "ai",
  "architecture",
  "cicd",
  "secrets",
];

export const INTEGRATION_CATEGORY_LABELS: Record<IntegrationCategory, string> = {
  recon: "Recon",
  vulnerability: "Vulnerability",
  "threat-intel": "Threat Intel",
  ticketing: "Ticketing",
  siem: "SIEM",
  soar: "SOAR",
  communication: "Communication",
  data: "Data",
  identity: "Identity",
  mcp: "MCP",
  ai: "AI",
  architecture: "Architecture",
  cicd: "CI / CD",
  secrets: "Secrets",
};

export const INTEGRATION_CATALOG: IntegrationCatalogEntry[] = [
  // ─── Recon ──────────────────────────────────────────────────────────────────
  {
    key: "shodan",
    name: "Shodan",
    category: "recon",
    direction: "inbound",
    auth: "api-key",
    description:
      "Internet-facing assets, open ports, service banners and discovered technologies for every range SwarmScan is authorized to touch.",
    agentBenefit:
      "Feeds the Recon agent's external attack-surface discovery and enriches hosts before fingerprinting spends requests.",
    cautions: [
      "Treating Shodan results as authoritative — data can be hours or days stale",
      "No asset-ownership validation before acting on discovered hosts",
      "Excessive API calls burning query credits",
    ],
    guardrails: { rateLimitPerMin: 12, scopeEnforced: true },
    fields: [
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "network_cidr", label: "Network CIDR", placeholder: "203.0.113.0/24" },
      { key: "history_days", label: "History window (days)", placeholder: "30" },
    ],
  },
  {
    key: "censys",
    name: "Censys",
    category: "recon",
    direction: "inbound",
    auth: "api-key",
    description:
      "Hosts, services, TLS certificates and the infrastructure relationships between them.",
    agentBenefit:
      "Discovers related infrastructure and certificate sprawl the crawler would never find from links alone.",
    cautions: [
      "Treating historical data as current",
      "Ignoring certificate-to-host relationships",
    ],
    guardrails: { rateLimitPerMin: 10, scopeEnforced: true },
    fields: [
      { key: "api_id", label: "API ID", required: true },
      { key: "api_secret", label: "API secret", secret: true, required: true },
      { key: "cert_watch_domain", label: "Certificate watch domain", placeholder: "acme-corp.com" },
    ],
  },
  {
    key: "securitytrails",
    name: "SecurityTrails",
    category: "recon",
    direction: "inbound",
    auth: "api-key",
    description: "DNS records, subdomain enumeration and historical DNS for owned domains.",
    agentBenefit:
      "Builds the domain and infrastructure relationship graph before the crawler spends a single request.",
    cautions: [
      "Treating historical subdomains as still active",
      "No ownership validation before scanning discovered hosts",
    ],
    guardrails: { rateLimitPerMin: 10, scopeEnforced: true },
    fields: [
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "root_domain", label: "Root domain", required: true, placeholder: "acme-corp.com" },
    ],
  },
  {
    key: "greynoise",
    name: "GreyNoise",
    category: "recon",
    direction: "inbound",
    auth: "api-key",
    description:
      "Internet-wide scanner traffic and background-noise classification for every IP touching your perimeter.",
    agentBenefit:
      "Reduces noise so agents prioritize genuinely unusual activity over mass-internet scanning.",
    cautions: [
      "Automatically suppressing events purely on classification",
      "Treating noise classification as definitive",
    ],
    guardrails: { rateLimitPerMin: 30 },
    fields: [
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "noise_ttl_hours", label: "Noise cache TTL (hours)", placeholder: "24" },
    ],
  },
  {
    key: "urlscan",
    name: "URLScan",
    category: "recon",
    direction: "inbound",
    auth: "api-key",
    description:
      "URL, domain and webpage analysis with rendered DOM, resources and hosting infrastructure.",
    agentBenefit:
      "Adds safe web context to suspicious URL and domain investigations without the scanner visiting them directly.",
    cautions: [
      "Uploading sensitive internal URLs to a public service",
      "Ignoring scan visibility settings",
      "Trusting a single scan as ground truth",
    ],
    guardrails: { rateLimitPerMin: 10, dataMinimization: true },
    fields: [
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "visibility", label: "Scan visibility", required: true, placeholder: "unlisted" },
    ],
  },

  // ─── Vulnerability ──────────────────────────────────────────────────────────
  {
    key: "nuclei",
    name: "Nuclei",
    category: "vulnerability",
    direction: "inbound",
    auth: "native",
    description:
      "Template-based automated security validation complementing SwarmScan agents with community detection logic.",
    agentBenefit:
      "Runs targeted, approved template checks against technologies the Fingerprint agent has already identified.",
    cautions: [
      "Scanning targets outside authorized scope",
      "Running the entire template library unchecked",
      "No rate limits between template executions",
      "Treating template matches as confirmed vulnerabilities — they stay suspected until a second technique confirms",
    ],
    guardrails: { rateLimitPerMin: 6, scopeEnforced: true },
    fields: [
      { key: "template_policy", label: "Template policy", required: true, placeholder: "reviewed-only" },
      { key: "rate_limit_per_sec", label: "Rate limit (req/sec)", placeholder: "5" },
      { key: "concurrency", label: "Concurrency", placeholder: "8" },
    ],
  },
  {
    key: "nuclei-templates",
    name: "Nuclei Templates",
    category: "vulnerability",
    direction: "inbound",
    auth: "native",
    description:
      "The detection-logic layer — which template families the AI may select per discovered technology.",
    agentBenefit:
      "Selects targeted security checks based on fingerprinted technology instead of spraying every template at every host.",
    cautions: [
      "Blindly trusting community templates",
      "No review or provenance tracking",
      "Unpinned versions drifting between runs",
      "Outdated templates producing false positives",
    ],
    guardrails: { rateLimitPerMin: 6, pinnedVersion: "repo_ref" },
    fields: [
      {
        key: "repo_ref",
        label: "Repository ref (pinned)",
        required: true,
        placeholder: "v3.2.1 — pinned tag, never latest",
      },
      { key: "review_policy", label: "Review policy", required: true, placeholder: "reviewed-only" },
      { key: "update_schedule", label: "Update schedule", placeholder: "weekly" },
    ],
  },

  // ─── Threat Intel ───────────────────────────────────────────────────────────
  {
    key: "virustotal",
    name: "VirusTotal",
    category: "threat-intel",
    direction: "inbound",
    auth: "api-key",
    description: "Hash, URL, domain and IP reputation with relationship graphs across 70+ engines.",
    agentBenefit: "IOC enrichment and malware / infrastructure correlation during triage.",
    cautions: [
      "Treating engine detection count as truth",
      "Uploading sensitive data to a public service",
      "Ignoring sample age and timestamps",
    ],
    guardrails: { rateLimitPerMin: 4, dataMinimization: true },
    fields: [
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "max_age_days", label: "Max indicator age (days)", placeholder: "30" },
    ],
  },
  {
    key: "misp",
    name: "MISP",
    category: "threat-intel",
    direction: "inbound",
    auth: "api-key",
    description: "Structured IOC, event and threat-intelligence sharing with community galaxies.",
    agentBenefit: "Correlates alerts with known campaigns, actors and indicator clusters.",
    cautions: [
      "Importing IOCs without confidence or expiration metadata",
      "Duplicate IOCs across events",
      "Importing everything indiscriminately",
      "Poor sharing controls leaking partner data",
    ],
    guardrails: { rateLimitPerMin: 6 },
    fields: [
      { key: "url", label: "MISP URL", required: true, placeholder: "https://misp.acme-corp.internal" },
      { key: "api_key", label: "Auth key", secret: true, required: true },
      { key: "event_ttl_days", label: "Event TTL (days)", placeholder: "90" },
    ],
  },
  {
    key: "otx",
    name: "AlienVault OTX",
    category: "threat-intel",
    direction: "inbound",
    auth: "api-key",
    description: "Community-sourced IOC pulses and threat-intelligence relationships.",
    agentBenefit: "Additional IOC enrichment and relationship context when primary sources disagree.",
    cautions: [
      "Treating community-sourced data as verified",
      "Ignoring pulse age and source reputation",
    ],
    guardrails: { rateLimitPerMin: 10 },
    fields: [
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "pulse_ttl_days", label: "Pulse TTL (days)", placeholder: "14" },
    ],
  },

  // ─── Ticketing ──────────────────────────────────────────────────────────────
  {
    key: "jira",
    name: "Jira Service Management",
    category: "ticketing",
    direction: "outbound",
    auth: "token",
    description: "Vulnerability, incident and remediation tracking tied to engineering workflows.",
    agentBenefit:
      "Converts validated findings into owned, SLA-tracked remediation tickets — deduplicated by evidence hash, not URL.",
    cautions: [
      "Duplicate tickets for the same root cause",
      "No ownership or SLA mapping on ticket create",
      "Dumping raw alerts into ticket bodies",
      "Sensitive data leakage in descriptions",
    ],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 20 },
    refPrefix: "VULN",
    fields: [
      { key: "url", label: "Instance URL", required: true, placeholder: "https://acme.atlassian.net" },
      { key: "project_key", label: "Project key", required: true, placeholder: "SEC" },
      { key: "api_token", label: "API token", secret: true },
      { key: "dedup", label: "Dedup policy", placeholder: "evidence-hash" },
    ],
  },
  {
    key: "servicenow",
    name: "ServiceNow",
    category: "ticketing",
    direction: "outbound",
    auth: "basic",
    description: "Incidents, CMDB configuration items, ownership and enterprise workflows.",
    agentBenefit: "Connects findings to the exact assets, services and owners that must remediate them.",
    cautions: [
      "Poor CI mapping — findings land on nonexistent assets",
      "Bypassing change management for urgent fixes",
      "Incorrect incident classification skewing metrics",
    ],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 15 },
    refPrefix: "INC",
    fields: [
      { key: "instance", label: "Instance", required: true, placeholder: "acme" },
      { key: "table", label: "Target table", placeholder: "x_swrm_scan_finding" },
      { key: "api_user", label: "API user" },
      { key: "api_password", label: "API password", secret: true },
    ],
  },
  {
    key: "zendesk",
    name: "Zendesk",
    category: "ticketing",
    direction: "outbound",
    auth: "token",
    description: "Support and ticket workflows for organizations running security through the helpdesk.",
    agentBenefit: "Routes security findings into existing support processes with familiar queues.",
    cautions: [
      "Alert-to-ticket overload flooding support agents",
      "Poor deduplication reopening solved issues",
      "Weak routing rules sending findings to the wrong queue",
    ],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 20 },
    refPrefix: "ZD",
    fields: [
      { key: "subdomain", label: "Subdomain", required: true, placeholder: "acme" },
      { key: "api_token", label: "API token", secret: true, required: true },
      { key: "routing_group", label: "Routing group", placeholder: "soc-tier-2" },
    ],
  },
  {
    key: "freshservice",
    name: "Freshservice",
    category: "ticketing",
    direction: "outbound",
    auth: "api-key",
    description: "ITSM with asset inventory, incident management and change workflows.",
    agentBenefit: "Tracks security-related IT tasks with clear asset and owner mapping.",
    cautions: [
      "Poor asset mapping to the CMDB",
      "Incorrect assignment rules",
      "Ticketing low-value suspected findings",
    ],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 15 },
    refPrefix: "FS",
    fields: [
      { key: "domain", label: "Domain", required: true, placeholder: "acme.freshservice.com" },
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "assignment_group", label: "Assignment group", placeholder: "security-ops" },
    ],
  },

  // ─── SIEM ───────────────────────────────────────────────────────────────────
  {
    key: "splunk",
    name: "Splunk",
    category: "siem",
    direction: "outbound",
    auth: "token",
    description: "Centralized event search and correlation across the enterprise.",
    agentBenefit: "Investigates users, hosts, IPs and historical events around every validated finding.",
    cautions: [
      "Unrestricted SPL execution",
      "Expensive unbounded queries",
      "Huge result sets overwhelming analysis",
      "Missing search time limits",
    ],
    guardrails: { rateLimitPerMin: 12, dataMinimization: true },
    refPrefix: "EVT",
    fields: [
      { key: "hec_url", label: "HEC endpoint", placeholder: "https://splunk.acme.internal:8088" },
      { key: "hec_token", label: "HEC token", secret: true },
      { key: "index", label: "Index", placeholder: "swarmscan" },
      { key: "sourcetype", label: "Sourcetype", placeholder: "swarm:finding" },
    ],
  },
  {
    key: "sentinel",
    name: "Microsoft Sentinel",
    category: "siem",
    direction: "outbound",
    auth: "oauth2",
    description: "Cloud SIEM — incidents, entities and KQL analytics across Microsoft telemetry.",
    agentBenefit: "Correlates identity, endpoint, cloud and network telemetry with scan findings.",
    cautions: [
      "Unrestricted KQL execution",
      "Poor workspace isolation",
      "Excessive API permissions",
    ],
    guardrails: { rateLimitPerMin: 10, dataMinimization: true },
    refPrefix: "EVT",
    fields: [
      { key: "tenant_id", label: "Tenant ID", required: true },
      { key: "client_id", label: "Client ID", required: true },
      { key: "client_secret", label: "Client secret", secret: true, required: true },
      { key: "workspace_id", label: "Workspace ID" },
    ],
  },
  {
    key: "qradar",
    name: "IBM QRadar",
    category: "siem",
    direction: "outbound",
    auth: "token",
    description: "Offenses, events and correlation rules for on-premise security operations.",
    agentBenefit: "Investigates offenses and retrieves supporting evidence for scanner findings.",
    cautions: [
      "Treating offense severity as final risk",
      "Excessive event retrieval bloating context",
    ],
    guardrails: { rateLimitPerMin: 10 },
    refPrefix: "EVT",
    fields: [
      { key: "console_url", label: "Console URL", required: true, placeholder: "https://qradar.acme.internal" },
      { key: "api_token", label: "SEC token", secret: true, required: true },
      { key: "offense_retention_days", label: "Offense retention (days)", placeholder: "90" },
    ],
  },
  {
    key: "elastic",
    name: "Elastic Security",
    category: "siem",
    direction: "outbound",
    auth: "api-key",
    description: "Security telemetry, detection rules and investigation on the Elastic stack.",
    agentBenefit: "Correlates endpoint, network and authentication telemetry with findings.",
    cautions: [
      "Unbounded queries",
      "Huge documents blown into context windows",
      "Weak index-level permissions",
    ],
    guardrails: { rateLimitPerMin: 12 },
    refPrefix: "EVT",
    fields: [
      { key: "kibana_url", label: "Kibana URL", placeholder: "https://kibana.acme.internal" },
      { key: "api_key", label: "API key", secret: true },
      { key: "index", label: "Index", placeholder: "swarmscan-findings" },
      { key: "pipeline", label: "Ingest pipeline", placeholder: "swarm-tls" },
    ],
  },
  {
    key: "gcp-secops",
    name: "Google Security Operations",
    category: "siem",
    direction: "outbound",
    auth: "oauth2",
    description: "Centralized security analytics and investigation (formerly Chronicle).",
    agentBenefit: "Correlates enterprise security telemetry with scan findings at search-engine scale.",
    cautions: [
      "Poor source normalization",
      "Weak access controls",
      "Excessive query scope",
    ],
    guardrails: { rateLimitPerMin: 10 },
    refPrefix: "EVT",
    fields: [
      { key: "project_id", label: "Project ID", required: true },
      { key: "credentials_json", label: "Service-account JSON", secret: true, required: true },
      { key: "region", label: "Region", placeholder: "us" },
    ],
  },
  {
    key: "wazuh",
    name: "Wazuh",
    category: "siem",
    direction: "outbound",
    auth: "basic",
    description: "Open-source endpoint events, vulnerability detection and file-integrity monitoring.",
    agentBenefit: "Adds endpoint and host-level context — processes, FIM changes — to findings.",
    cautions: [
      "Treating every alert as an incident",
      "Poor asset mapping",
    ],
    guardrails: { rateLimitPerMin: 15 },
    refPrefix: "EVT",
    fields: [
      { key: "manager_url", label: "Manager URL", required: true, placeholder: "https://wazuh.acme.internal:55000" },
      { key: "api_user", label: "API user", required: true },
      { key: "api_password", label: "API password", secret: true, required: true },
    ],
  },

  // ─── SOAR ───────────────────────────────────────────────────────────────────
  {
    key: "cortex-xsoar",
    name: "Cortex XSOAR",
    category: "soar",
    direction: "outbound",
    auth: "api-key",
    description: "Enrichment, investigation and response playbooks with human-in-the-loop gates.",
    agentBenefit: "Executes controlled security workflows the AI proposes and analysts approve.",
    cautions: [
      "Unrestricted AI playbook execution",
      "No approval steps",
      "Weak rollback on failed actions",
    ],
    guardrails: { requiresApproval: true, rateLimitPerMin: 5 },
    refPrefix: "PB",
    fields: [
      { key: "server_url", label: "Server URL", required: true },
      { key: "api_key", label: "API key", secret: true, required: true },
      {
        key: "playbook_allowlist",
        label: "Playbook allowlist",
        required: true,
        placeholder: "approved-playbooks",
      },
    ],
  },
  {
    key: "splunk-soar",
    name: "Splunk SOAR",
    category: "soar",
    direction: "outbound",
    auth: "token",
    description: "Security orchestration, automation and response tied to Splunk investigations.",
    agentBenefit: "Automates repeatable investigation and response behind approval gates.",
    cautions: [
      "Over-automating remediation",
      "Excessive integration privileges",
    ],
    guardrails: { requiresApproval: true, rateLimitPerMin: 5 },
    refPrefix: "PB",
    fields: [
      { key: "server_url", label: "Server URL", required: true },
      { key: "api_token", label: "API token", secret: true, required: true },
      { key: "max_auto_actions", label: "Max auto-actions", placeholder: "3" },
    ],
  },
  {
    key: "tines",
    name: "Tines",
    category: "soar",
    direction: "outbound",
    auth: "token",
    description: "Low-code security automation connecting email, chat and case tools.",
    agentBenefit: "Connects multiple security tools into multi-step workflows.",
    cautions: [
      "Over-complex workflows nobody can audit",
      "Hard-coded secrets in stories",
      "Poor error handling silently dropping events",
    ],
    guardrails: { requiresApproval: true, rateLimitPerMin: 5 },
    refPrefix: "TN",
    fields: [
      { key: "tenant_url", label: "Tenant URL", required: true, placeholder: "https://acme.tines.com" },
      { key: "api_token", label: "API token", secret: true, required: true },
      { key: "story_ids", label: "Story IDs", placeholder: "soc-enrichment,soc-response" },
    ],
  },
  {
    key: "swimlane",
    name: "Swimlane",
    category: "soar",
    direction: "outbound",
    auth: "token",
    description: "Case management and security automation for repeatable response.",
    agentBenefit: "Automates repeatable security cases with full audit trails.",
    cautions: ["Poor workflow governance", "Excessive privileges"],
    guardrails: { requiresApproval: true, rateLimitPerMin: 5 },
    refPrefix: "SL",
    fields: [
      { key: "url", label: "Application URL", required: true },
      { key: "api_token", label: "API token", secret: true, required: true },
      { key: "workflow_ids", label: "Workflow IDs", placeholder: "vuln-response" },
    ],
  },
  {
    key: "torq",
    name: "Torq",
    category: "soar",
    direction: "outbound",
    auth: "token",
    description: "Security workflow automation across modern SOC toolchains.",
    agentBenefit: "Automates multi-system security workflows with approval gates.",
    cautions: ["Overprivileged integrations", "No approval gates on destructive steps"],
    guardrails: { requiresApproval: true, rateLimitPerMin: 5 },
    refPrefix: "TQ",
    fields: [
      { key: "url", label: "Endpoint URL", required: true },
      { key: "api_token", label: "API token", secret: true, required: true },
      { key: "approval_gate_ids", label: "Approval gate IDs", placeholder: "soc-lead" },
    ],
  },
  {
    key: "shuffle",
    name: "Shuffle",
    category: "soar",
    direction: "outbound",
    auth: "token",
    description: "Open-source workflow automation for self-hosted SOAR pipelines.",
    agentBenefit: "Connects open-source security tools into governed workflows.",
    cautions: ["Poor secret management", "Unvalidated community workflows"],
    guardrails: { requiresApproval: true, pinnedVersion: "workflow_hash", rateLimitPerMin: 5 },
    refPrefix: "SH",
    fields: [
      { key: "base_url", label: "Base URL", required: true },
      { key: "api_token", label: "API token", secret: true, required: true },
      {
        key: "workflow_hash",
        label: "Workflow hash (pinned)",
        required: true,
        placeholder: "commit hash — never latest",
      },
    ],
  },
  {
    key: "cloudflare-waf",
    name: "Cloudflare WAF",
    category: "soar",
    direction: "outbound",
    auth: "token",
    description: "Edge Web Application Firewall custom rulesets for instant virtual patching.",
    agentBenefit: "Automatically deploys scoped custom expression rules to block verified exploits at the CDN edge.",
    cautions: [
      "Overly broad regex expressions blocking legitimate traffic",
      "Deploying without rate-limit or path scoping",
    ],
    guardrails: { requiresApproval: true, rateLimitPerMin: 10 },
    refPrefix: "CF-WAF",
    fields: [
      { key: "zone_id", label: "Zone ID", required: true, placeholder: "023e105f4ecef8ad9ca31a8372d0c353" },
      { key: "api_token", label: "API token", secret: true, required: true },
      { key: "ruleset_id", label: "Custom Ruleset ID", placeholder: "auto-resolved if omitted" },
    ],
  },
  {
    key: "aws-waf",
    name: "AWS WAF v2",
    category: "soar",
    direction: "outbound",
    auth: "api-key",
    description: "AWS WAF v2 WebACL rule groups for CloudFront, ALB, and API Gateway virtual patching.",
    agentBenefit: "Deploys structured JSON WebACL statements (SqliMatch, XssMatch, RegexMatch) to shield AWS workloads.",
    cautions: [
      "Exceeding WebACL WCU capacity limits",
      "Missing Scope (REGIONAL vs CLOUDFRONT) alignment",
    ],
    guardrails: { requiresApproval: true, rateLimitPerMin: 10 },
    refPrefix: "AWS-WAF",
    fields: [
      { key: "web_acl_arn", label: "WebACL ARN", required: true, placeholder: "arn:aws:wafv2:us-east-1:..." },
      { key: "access_key_id", label: "IAM Access Key ID", required: true },
      { key: "secret_access_key", label: "IAM Secret Access Key", secret: true, required: true },
    ],
  },

  // ─── Communication ──────────────────────────────────────────────────────────
  {
    key: "slack",
    name: "Slack",
    category: "communication",
    direction: "outbound",
    auth: "token",
    description: "SOC notifications, collaboration and analyst approvals in channel.",
    agentBenefit:
      "Real-time investigation summaries and one-click analyst approvals for gate-restricted actions.",
    cautions: [
      "Sensitive finding data posted to broad channels",
      "Alert spam causing analyst fatigue",
      "Privileged chat commands without confirmation",
    ],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 20, dataMinimization: true },
    refPrefix: "MSG",
    fields: [
      { key: "bot_token", label: "Bot token", secret: true, required: true },
      { key: "channel_routing", label: "Channel routing", required: true, placeholder: "#soc-critical" },
      { key: "notify_bands", label: "Notify on bands", placeholder: "confirmed" },
    ],
  },
  {
    key: "teams",
    name: "Microsoft Teams",
    category: "communication",
    direction: "outbound",
    auth: "webhook",
    description: "SOC collaboration and incident communication in Microsoft Teams.",
    agentBenefit: "Collaboration, notifications and approval workflows where the SOC already works.",
    cautions: [
      "Excessive sensitive information in channels",
      "Uncontrolled command handling",
    ],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 15, dataMinimization: true },
    refPrefix: "MSG",
    fields: [
      { key: "webhook_url", label: "Incoming webhook URL", secret: true, required: true },
      { key: "team_channel", label: "Team channel", placeholder: "Security Operations" },
    ],
  },
  {
    key: "email",
    name: "Email (SMTP)",
    category: "communication",
    direction: "outbound",
    auth: "basic",
    description: "Escalation, reporting and notifications via SMTP.",
    agentBenefit: "Incident escalation and executive reporting outside chat tools.",
    cautions: [
      "Sensitive-data leakage to broad distribution lists",
      "Alert flooding inboxes",
      "Weak sender controls enabling spoofing",
    ],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 10, dataMinimization: true },
    refPrefix: "ML",
    fields: [
      { key: "smtp_host", label: "SMTP host", required: true, placeholder: "smtp.acme-corp.com" },
      { key: "smtp_port", label: "SMTP port", placeholder: "587" },
      { key: "from_address", label: "From address", required: true, placeholder: "swarmscan@acme-corp.com" },
      { key: "digest_mode", label: "Digest mode", placeholder: "hourly-digest" },
    ],
  },

  // ─── Data ───────────────────────────────────────────────────────────────────
  {
    key: "postgresql",
    name: "PostgreSQL",
    category: "data",
    direction: "inbound",
    auth: "native",
    description: "Primary state store — assets, findings, investigation state and metadata.",
    agentBenefit: "Persistent agent memory and state; finding deduplication across scans.",
    cautions: [
      "Unrestricted AI SQL or write access",
      "Secrets stored in plaintext columns",
      "Poor tenant isolation",
    ],
    guardrails: { rateLimitPerMin: 60 },
    fields: [
      { key: "connection_string", label: "Connection string", secret: true, required: true },
      { key: "schema_name", label: "Schema", placeholder: "swarmscan" },
      { key: "statement_timeout_ms", label: "Statement timeout (ms)", placeholder: "5000" },
    ],
  },
  {
    key: "mysql",
    name: "MySQL",
    category: "data",
    direction: "inbound",
    auth: "native",
    description: "Structured security-agent data for MySQL-standard organizations.",
    agentBenefit: "Persistent asset and investigation data alongside existing systems.",
    cautions: [
      "Excessive privileges granted to the agent",
      "Unrestricted queries",
      "Weak schema controls",
    ],
    guardrails: { rateLimitPerMin: 60, readOnly: true },
    fields: [
      { key: "dsn", label: "DSN", secret: true, required: true },
      { key: "access_mode", label: "Access mode", required: true, placeholder: "read-only" },
      { key: "statement_timeout_ms", label: "Statement timeout (ms)", placeholder: "5000" },
    ],
  },
  {
    key: "elasticsearch",
    name: "Elasticsearch",
    category: "data",
    direction: "inbound",
    auth: "api-key",
    description: "Large-scale event and finding search beyond the SIEM indexes.",
    agentBenefit: "Fast historical security-context retrieval for investigations.",
    cautions: [
      "Unbounded searches",
      "Excessive data returned to the LLM",
      "Weak index-level controls",
    ],
    guardrails: { rateLimitPerMin: 30, readOnly: true },
    fields: [
      { key: "nodes_url", label: "Nodes URL", required: true, placeholder: "https://es.acme.internal:9200" },
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "index_pattern", label: "Index pattern", placeholder: "swarmscan-*" },
      { key: "max_result_window", label: "Max result window", placeholder: "1000" },
    ],
  },

  // ─── Identity ───────────────────────────────────────────────────────────────
  {
    key: "entra-id",
    name: "Microsoft Entra ID",
    category: "identity",
    direction: "inbound",
    auth: "oauth2",
    description: "Users, groups, applications and identity context from Entra ID.",
    agentBenefit: "Adds identity context — who owns what, who touched what — to investigations.",
    cautions: [
      "Excessive API permissions",
      "Weak RBAC on the integration principal",
      "No approval for privileged identity actions",
    ],
    guardrails: { rateLimitPerMin: 20, readOnly: true },
    fields: [
      { key: "tenant_id", label: "Tenant ID", required: true },
      { key: "client_id", label: "Client ID", required: true },
      { key: "client_secret", label: "Client secret", secret: true, required: true },
      { key: "graph_scope", label: "Graph scope", placeholder: "User.Read.All" },
    ],
  },
  {
    key: "okta",
    name: "Okta",
    category: "identity",
    direction: "inbound",
    auth: "token",
    description: "Authentication and identity telemetry from Okta.",
    agentBenefit: "Correlates suspicious authentication activity with scan findings.",
    cautions: [
      "Overprivileged tokens",
      "Weak token rotation",
      "Uncontrolled actions on identity objects",
    ],
    guardrails: { rateLimitPerMin: 20, readOnly: true },
    fields: [
      { key: "org_domain", label: "Org domain", required: true, placeholder: "acme.okta.com" },
      { key: "api_token", label: "API token", secret: true, required: true },
      { key: "token_rotation_days", label: "Token rotation (days)", placeholder: "30" },
    ],
  },

  // ─── MCP ────────────────────────────────────────────────────────────────────
  {
    key: "mcp-recon",
    name: "Recon MCP",
    category: "mcp",
    direction: "inbound",
    auth: "token",
    description: "Standardized MCP access to recon tooling behind one policy boundary.",
    agentBenefit:
      "Gives the AI controlled recon and enrichment capabilities with per-tool authorization.",
    cautions: ["No target validation", "Exposing unrestricted tools to the model"],
    guardrails: { scopeEnforced: true, rateLimitPerMin: 20 },
    fields: [
      { key: "server_url", label: "MCP server URL", required: true },
      {
        key: "tool_allowlist",
        label: "Tool allowlist",
        required: true,
        placeholder: "dns_lookup,whois,cert_search",
      },
      { key: "scope_enforced", label: "Scope enforced", placeholder: "true" },
    ],
  },
  {
    key: "mcp-nuclei",
    name: "Nuclei MCP",
    category: "mcp",
    direction: "inbound",
    auth: "token",
    description: "Standardized Nuclei scanning and template operations over MCP.",
    agentBenefit: "Lets the AI invoke approved vulnerability checks against in-scope targets only.",
    cautions: ["No scope controls", "Arbitrary template selection", "No rate limiting"],
    guardrails: { scopeEnforced: true, rateLimitPerMin: 10 },
    fields: [
      { key: "server_url", label: "MCP server URL", required: true },
      { key: "template_policy", label: "Template policy", required: true, placeholder: "reviewed-only" },
      { key: "rate_limit_per_min", label: "Rate limit (per min)", placeholder: "6" },
    ],
  },
  {
    key: "mcp-threat-intel",
    name: "Threat Intel MCP",
    category: "mcp",
    direction: "inbound",
    auth: "token",
    description: "Unified MCP interface across VirusTotal, MISP and OTX.",
    agentBenefit: "Cross-source IOC enrichment in one call with source and confidence metadata.",
    cautions: [
      "No source or confidence metadata on results",
      "Excessive data returned to the LLM",
    ],
    guardrails: { rateLimitPerMin: 15, dataMinimization: true },
    fields: [
      { key: "server_url", label: "MCP server URL", required: true },
      { key: "sources", label: "Sources", placeholder: "virustotal,misp,otx" },
      { key: "max_ioc_per_query", label: "Max IOCs per query", placeholder: "50" },
    ],
  },
  {
    key: "mcp-siem",
    name: "SIEM MCP",
    category: "mcp",
    direction: "inbound",
    auth: "token",
    description: "Unified SIEM investigation interface — one query grammar, many backends.",
    agentBenefit: "Lets the AI search and correlate telemetry without direct SIEM credentials.",
    cautions: ["Unrestricted queries", "Huge result sets", "No tenant isolation"],
    guardrails: { rateLimitPerMin: 12, readOnly: true },
    fields: [
      { key: "server_url", label: "MCP server URL", required: true },
      { key: "query_timeout_sec", label: "Query timeout (sec)", placeholder: "30" },
      { key: "tenant_isolation", label: "Tenant isolation", placeholder: "true" },
    ],
  },
  {
    key: "mcp-ticketing",
    name: "Ticketing MCP",
    category: "mcp",
    direction: "outbound",
    auth: "token",
    description: "Unified Jira / ServiceNow / ITSM interface for structured ticket creation.",
    agentBenefit: "Creates structured incidents and remediation tasks with deduplication.",
    cautions: ["Automatic duplicate tickets", "Excessive write permissions"],
    guardrails: { dedupeByEvidence: true, rateLimitPerMin: 15 },
    refPrefix: "MCP",
    fields: [
      { key: "server_url", label: "MCP server URL", required: true },
      { key: "dedupe_policy", label: "Dedupe policy", required: true, placeholder: "evidence-hash" },
      { key: "write_scope", label: "Write scope", placeholder: "create-only" },
    ],
  },
  {
    key: "mcp-soar",
    name: "SOAR MCP",
    category: "mcp",
    direction: "outbound",
    auth: "token",
    description: "Controlled MCP access to automation and response playbooks.",
    agentBenefit: "Allows the AI to trigger approved security workflows with analyst sign-off.",
    cautions: ["Destructive actions without approval", "No action allowlist"],
    guardrails: { requiresApproval: true, rateLimitPerMin: 5 },
    refPrefix: "MCP",
    fields: [
      { key: "server_url", label: "MCP server URL", required: true },
      {
        key: "action_allowlist",
        label: "Action allowlist",
        required: true,
        placeholder: "isolate_host,block_ip",
      },
      { key: "approval_required", label: "Approval required", placeholder: "true" },
    ],
  },
  {
    key: "mcp-database",
    name: "Database MCP",
    category: "mcp",
    direction: "inbound",
    auth: "token",
    description: "Standard MCP database and search access for agent memory.",
    agentBenefit: "Provides persistent security context with row-level controls.",
    cautions: ["Default write access", "Unrestricted SQL", "Poor row-level security"],
    guardrails: { readOnly: true, rateLimitPerMin: 30 },
    fields: [
      { key: "server_url", label: "MCP server URL", required: true },
      { key: "default_access", label: "Default access", required: true, placeholder: "read-only" },
      { key: "row_level_security", label: "Row-level security", placeholder: "enabled" },
    ],
  },

  // ─── AI ─────────────────────────────────────────────────────────────────────
  {
    key: "llm-provider",
    name: "LLM / AI Provider",
    category: "ai",
    direction: "inbound",
    auth: "api-key",
    description: "Reasoning, correlation, summarization and orchestration brain for the agent swarm.",
    agentBenefit: "Converts multi-tool evidence into investigations, verdicts and reports.",
    cautions: [
      "Excessive tool privileges granted to the model",
      "Unsupported conclusions without evidence grounding",
      "Unnecessary sensitive data in prompts",
    ],
    guardrails: { rateLimitPerMin: 30, dataMinimization: true },
    fields: [
      { key: "provider", label: "Provider", required: true, placeholder: "zai" },
      { key: "model", label: "Model", required: true, placeholder: "glm-4.7" },
      { key: "api_key", label: "API key", secret: true, required: true },
      { key: "max_output_tokens", label: "Max output tokens", placeholder: "4096" },
    ],
  },

  // ─── Architecture ───────────────────────────────────────────────────────────
  {
    key: "mcp-gateway",
    name: "MCP Gateway / Policy Layer",
    category: "architecture",
    direction: "inbound",
    auth: "token",
    description:
      "Centralized authentication, authorization, RBAC, auditing and rate limits for every MCP tool call.",
    agentBenefit: "Creates the security boundary between the AI agent and enterprise systems.",
    cautions: [
      "Treating MCP itself as authorization",
      "No audit trail",
      "No rate limiting",
      "No approval controls",
    ],
    guardrails: { rateLimitPerMin: 120 },
    fields: [
      { key: "gateway_url", label: "Gateway URL", required: true },
      { key: "policy_bundle", label: "Policy bundle", required: true, placeholder: "swarmscan-policy-v7" },
      { key: "audit_retention_days", label: "Audit retention (days)", placeholder: "365" },
      { key: "rate_limit_per_min", label: "Rate limit (per min)", placeholder: "120" },
    ],
  },

  // ─── CI / CD (existing keys — github / gitlab / jenkins match the DB) ───────
  {
    key: "github",
    name: "GitHub Actions",
    category: "cicd",
    direction: "inbound",
    auth: "token",
    description: "CI pipeline gating — SwarmScan check runs block merges on policy verdicts.",
    agentBenefit: "Shifts scanning left: every pull request gets a range-scan plan and a pass/fail gate.",
    cautions: [
      "Gating on suspected findings causing alert fatigue",
      "Broad repo tokens where a GitHub App would suffice",
    ],
    guardrails: { rateLimitPerMin: 30 },
    fields: [
      { key: "app_name", label: "GitHub App", placeholder: "swarmscan-guard[bot]" },
      { key: "workflow", label: "Gate workflow", placeholder: "swarmscan-gate.yml" },
      { key: "fail_on", label: "Fail on", placeholder: "high" },
      { key: "webhook_secret", label: "Webhook secret", secret: true },
    ],
  },
  {
    key: "gitlab",
    name: "GitLab CI",
    category: "cicd",
    direction: "inbound",
    auth: "token",
    description: "Pipeline-integrated scanning for GitLab-hosted repositories.",
    agentBenefit: "Merge-request gating with the same policy engine as the GitHub App.",
    cautions: [
      "Over-broad API scopes",
      "Pipeline secrets stored in plain variables",
    ],
    guardrails: { rateLimitPerMin: 30 },
    fields: [
      { key: "instance_url", label: "Instance URL", placeholder: "https://gitlab.acme-corp.com" },
      { key: "pipeline", label: "Pipeline path", placeholder: "security/swarmscan" },
      { key: "fail_on", label: "Fail on", placeholder: "high" },
      { key: "access_token", label: "Access token", secret: true },
    ],
  },
  {
    key: "jenkins",
    name: "Jenkins",
    category: "cicd",
    direction: "inbound",
    auth: "token",
    description: "Build-time scanning for legacy Jenkins pipelines.",
    agentBenefit: "Gates artifact promotion on scan verdicts.",
    cautions: [
      "Unprotected Jenkinsfile injection paths",
      "Stale credentials on build agents",
    ],
    guardrails: { rateLimitPerMin: 30 },
    fields: [
      { key: "controller_url", label: "Controller URL", placeholder: "https://jenkins.acme-corp.com" },
      { key: "job", label: "Gate job", placeholder: "swarmscan-gate" },
      { key: "credential", label: "Credential", placeholder: "vault-approle" },
      { key: "api_token", label: "API token", secret: true },
    ],
  },

  // ─── Secrets ────────────────────────────────────────────────────────────────
  {
    key: "vault",
    name: "HashiCorp Vault",
    category: "secrets",
    direction: "inbound",
    auth: "token",
    description: "Centralized secret management for every integration credential on this page.",
    agentBenefit:
      "Dynamic, rotating credentials — the control plane never stores third-party secrets in plaintext.",
    cautions: [
      "Long-lived static tokens",
      "No lease auditing",
      "Broad policy grants per integration",
    ],
    guardrails: { rateLimitPerMin: 60 },
    fields: [
      { key: "vault_url", label: "Vault URL", placeholder: "https://vault.acme-corp.internal" },
      { key: "path", label: "Secrets path", placeholder: "kv/swarmscan-creds" },
      { key: "auth", label: "Auth method", placeholder: "kubernetes" },
      { key: "role_id", label: "AppRole role ID", secret: true },
    ],
  },
];

/** O(1) catalog lookup by stable key. */
export function integrationCatalogFor(key: string): IntegrationCatalogEntry | undefined {
  return INTEGRATION_CATALOG.find((entry) => entry.key === key);
}

/** Field spec lookup — used by config validation on both sides of the wire. */
export function integrationFieldSpec(
  key: string,
  fieldKey: string
): IntegrationFieldSpec | undefined {
  return integrationCatalogFor(key)?.fields.find((f) => f.key === fieldKey);
}
