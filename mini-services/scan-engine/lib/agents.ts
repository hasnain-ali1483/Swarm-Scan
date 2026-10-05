// ─── SwarmScan agent registry (execution-plane mirror) ───────────────────────
// Mirrored from the control-plane contract /home/z/my-project/src/lib/swarm/agents-catalog.ts.
// The scan-engine is an independent project and cannot import from src/,
// so the essential fields are copied here. Keep in sync with the catalog.
//
// stage = DAG stage in the scan plan: agents within a stage run in parallel,
// a stage starts when ALL agents of the previous stage reached a terminal
// status (done | blocked | skipped | killed).
//
// The registry has three families:
//   • classic spec agents   — the original pipeline (recon → evasion)
//   • unorthodox agents     — attacker tradecraft that no textbook teaches
//                             (request smuggling, cache poisoning, host-header
//                             routing confusion, edge-appliance pre-auth RCE,
//                             password spraying, repo looting, …). Marked with
//                             unorthodox: true + a tradecraft one-liner.
//   • dynamic agents        — never part of the static plan. They sit DORMANT
//                             until their spawn trigger fires at runtime (e.g.
//                             SSRF reached the metadata plane → PivotAgent),
//                             then join the DAG mid-scan. Marked dynamic: true
//                             with spawnOn + spawnOnDesc.

export type SafetyClass = "read-only" | "data-touching";

/** Runtime spawn condition for dynamic agents. */
export interface SpawnCondition {
  /** Spawn when ANY of these agents finished (done) with ≥1 finding. */
  agentKeys?: string[];
  /** Spawn when the scan produced ≥ N findings … */
  minFindings?: number;
  /** … from ≥ M distinct agents (prevents self-correlation). */
  distinctAgents?: number;
}

export interface AgentSpec {
  key: string;
  name: string;
  version: string;
  safetyClass: SafetyClass;
  category: string;
  states: string[];
  /** DAG stage (0–5). */
  stage: number;
  /** Short display tag used in live event messages, e.g. "injection.sql". */
  tag: string;
  /** dynamic agents spawn at runtime instead of being planned statically. */
  dynamic?: boolean;
  /** spawn trigger (dynamic agents only). */
  spawnOn?: SpawnCondition;
  /** human-readable trigger description for events + UI tooltips. */
  spawnOnDesc?: string;
  /** unorthodox = attacker tradecraft outside the textbook canon. */
  unorthodox?: boolean;
  /** one-line "why this hurts" for the unorthodox family. */
  tradecraft?: string;
}

export const AGENTS: AgentSpec[] = [
  // ── Classic pipeline ──────────────────────────────────────────────────────
  {
    key: "recon",
    name: "ReconAgent",
    version: "2.1.3",
    safetyClass: "read-only",
    category: "recon",
    states: ["passive_recon", "ct_logs", "passive_dns", "saas_takeover", "permutation", "active_diff", "asset_delta"],
    stage: 0,
    tag: "recon.dns",
  },
  {
    key: "fingerprint",
    name: "FingerprintAgent",
    version: "2.4.0",
    safetyClass: "read-only",
    category: "recon",
    states: ["signal_fusion", "static_hash", "favicon_hash", "waf_detect", "version_infer", "cve_map"],
    stage: 1,
    tag: "fingerprint.waf",
  },
  {
    key: "crawler",
    name: "CrawlerAgent",
    version: "3.0.1",
    safetyClass: "read-only",
    category: "discovery",
    states: ["fetch_js", "ast_parse", "route_enum", "form_interact", "param_mine", "waterfall_capture"],
    stage: 2,
    tag: "crawler.spa",
  },
  {
    key: "ssrf",
    name: "SSRFAgent",
    version: "1.9.2",
    safetyClass: "data-touching",
    category: "injection",
    states: ["scheme_matrix", "metadata_probe", "imds_v2", "dns_rebind", "redirect_chain", "verify"],
    stage: 2,
    tag: "ssrf.imds",
  },
  {
    key: "injection",
    name: "InjectionAgent",
    version: "1.4.0",
    safetyClass: "data-touching",
    category: "injection",
    states: ["analyze_surface", "build_grammar", "probe_error", "probe_boolean", "probe_time", "probe_oob", "verify", "escalate"],
    stage: 3,
    tag: "injection.sql",
  },
  {
    key: "xss",
    name: "XSSAgent",
    version: "2.2.7",
    safetyClass: "data-touching",
    category: "client",
    states: ["analyze_context", "dom_instrument", "probe_reflection", "probe_dom", "mxss_roundtrip", "csp_eval", "stored_check"],
    stage: 3,
    tag: "xss.dom",
  },
  {
    key: "fileops",
    name: "FileOpsAgent",
    version: "1.6.4",
    safetyClass: "data-touching",
    category: "files",
    states: ["wrapper_matrix", "filter_chain", "traversal_matrix", "upload_polyglot", "exec_oracle"],
    stage: 3,
    tag: "fileops.lfi",
  },
  {
    key: "deser",
    name: "DeserializationAgent",
    version: "1.3.8",
    safetyClass: "data-touching",
    category: "injection",
    states: ["classpath_infer", "gadget_select", "dns_first_stage", "escalate", "verify"],
    stage: 3,
    tag: "deser.gadget",
  },
  {
    key: "auth",
    name: "AuthAgent",
    version: "2.0.5",
    safetyClass: "data-touching",
    category: "authz",
    states: ["session_map", "idor_matrix", "jwt_probes", "race_test", "oauth_matrix", "session_verify"],
    stage: 4,
    tag: "auth.idor",
  },
  {
    key: "api",
    name: "APIAgent",
    version: "1.8.0",
    safetyClass: "data-touching",
    category: "api",
    states: ["spec_import", "coverage_matrix", "graphql_introspect", "field_suggest", "batch_probe", "mass_assign"],
    stage: 4,
    tag: "api.graphql",
  },
  {
    key: "crypto",
    name: "CryptographyAgent",
    version: "1.5.1",
    safetyClass: "read-only",
    category: "crypto",
    states: ["tls_audit", "cert_chain", "padding_oracle", "jwt_crypto", "entropy_sample"],
    stage: 4,
    tag: "crypto.tls",
  },
  {
    key: "cloud",
    name: "CloudAgent",
    version: "1.7.2",
    safetyClass: "read-only",
    category: "cloud",
    states: ["bucket_enum", "takeover_check", "imds_handle", "iam_sim"],
    stage: 4,
    tag: "cloud.s3",
  },
  {
    key: "correlator",
    name: "CorrelatorAgent",
    version: "2.3.0",
    safetyClass: "read-only",
    category: "correlation",
    states: ["graph_build", "path_plan", "chain_score", "poc_plan"],
    stage: 5,
    tag: "correlator.graph",
  },
  {
    key: "revisit",
    name: "RevisitAgent",
    version: "1.2.0",
    safetyClass: "read-only",
    category: "continuous",
    states: ["queue_check", "canary_readback", "cert_resweep", "key_rotation_check"],
    stage: 5,
    tag: "revisit.canary",
  },
  {
    key: "evasion",
    name: "EvasionAgent",
    version: "1.4.6",
    safetyClass: "read-only",
    category: "evasion",
    states: ["waf_profile", "transform_grammar", "bypass_test", "record_chain"],
    stage: 5,
    tag: "evasion.waf",
  },

  // ── Unorthodox tradecraft (not taught — what real attackers run) ──────────
  {
    key: "osint",
    name: "OSINTAgent",
    version: "1.2.0",
    safetyClass: "read-only",
    category: "osint",
    states: ["breach_corpus", "gharchive_diff", "code_search_dorks", "email_pattern", "wayback_diff", "harvest_score"],
    stage: 0,
    tag: "osint.corpus",
    unorthodox: true,
    tradecraft: "Real intrusions start with WHO you are, not what you expose — breach corpora, commit metadata and code-search dorks assemble a credential-targeting picture before a single packet is sent.",
  },
  {
    key: "edge",
    name: "EdgeDeviceAgent",
    version: "1.1.0",
    safetyClass: "data-touching",
    category: "perimeter",
    states: ["vpn_fingerprint", "banner_differential", "preauth_probe", "cve_chain_match", "session_leak_check", "verify"],
    stage: 1,
    tag: "edge.cve",
    unorthodox: true,
    tradecraft: "APTs don't scan web apps first — they mass-hunt SSL-VPN appliances for pre-auth RCE chains (Ivanti, Citrix Bleed, Fortinet, F5) because the edge device IS the perimeter.",
  },
  {
    key: "smuggling",
    name: "RequestSmugglingAgent",
    version: "1.0.4",
    safetyClass: "data-touching",
    category: "smuggling",
    states: ["differential_probe", "cl_te_desync", "te_cl_desync", "h2_downgrade", "queue_poison", "capture_verify"],
    stage: 2,
    tag: "smuggling.desync",
    unorthodox: true,
    tradecraft: "Front-end/back-end parser differentials (CL.TE, TE.CL, h2.CL) let an attacker smuggle a second request onto another user's connection — the closest thing to magic in web security.",
  },
  {
    key: "hostheader",
    name: "HostHeaderAgent",
    version: "1.0.2",
    safetyClass: "data-touching",
    category: "routing",
    states: ["vhost_map", "host_override_matrix", "absolute_uri_probe", "x_forwarded_matrix", "reset_poison_check", "cache_key_probe"],
    stage: 2,
    tag: "host.reset-poison",
    unorthodox: true,
    tradecraft: "The Host header is routing state — password-reset poisoning, cache-key manipulation and internal-vhost confusion turn a 'cosmetic' header into account takeover.",
  },
  {
    key: "gitrepo",
    name: "RepoLootAgent",
    version: "1.1.1",
    safetyClass: "read-only",
    category: "disclosure",
    states: ["dotgit_check", "object_recovery", "packed_refs_walk", "history_diff", "config_loot", "ci_pipeline_map"],
    stage: 2,
    tag: "git.loot",
    unorthodox: true,
    tradecraft: "An exposed .git is not 'information disclosure' — it is the source tree, every secret ever committed, and the CI pipeline in one loot bag.",
  },
  {
    key: "secrets",
    name: "SecretsHarvesterAgent",
    version: "1.3.0",
    safetyClass: "read-only",
    category: "secrets",
    states: ["bundle_sweep", "entropy_window", "sourcemap_recover", "token_shape_classify", "key_liveness_probe", "scope_map"],
    stage: 2,
    tag: "secrets.js",
    unorthodox: true,
    tradecraft: "Attackers grep JS bundles and sourcemaps for live keys before touching a login form — a staging key valid against production is the shortest path to the crown jewels.",
  },
  {
    key: "cachepoison",
    name: "CachePoisoningAgent",
    version: "1.0.3",
    safetyClass: "data-touching",
    category: "cache",
    states: ["cache_key_infer", "unkeyed_input_hunt", "poison_probe", "fat_get_test", "deception_path_matrix", "stored_capture"],
    stage: 3,
    tag: "cache.poison",
    unorthodox: true,
    tradecraft: "Unkeyed inputs poison the shared cache for every user; cache-deception paths make the cache serve another user's PII to you. No payload ever touches the app — the cache does the work.",
  },
  {
    key: "prototype",
    name: "PrototypePollutionAgent",
    version: "1.0.2",
    safetyClass: "data-touching",
    category: "client",
    states: ["merge_gadget_hunt", "proto_probe", "constructor_bypass", "gadget_chain_select", "exec_oracle", "verify"],
    stage: 3,
    tag: "proto.gadget",
    unorthodox: true,
    tradecraft: "Polluting Object.prototype is silent — but chained into RCE gadgets (child_process options, EJS/HBS render opts) it becomes pre-auth remote code execution.",
  },
  {
    key: "websocket",
    name: "WebSocketAgent",
    version: "1.0.1",
    safetyClass: "data-touching",
    category: "api",
    states: ["upgrade_capture", "origin_check_matrix", "cswsh_probe", "message_fuzz", "auth_replay", "subprotocol_confuse"],
    stage: 3,
    tag: "ws.orig",
  },
  {
    key: "saml",
    name: "SamlAgent",
    version: "1.1.0",
    safetyClass: "data-touching",
    category: "authz",
    states: ["metadata_parse", "xsw_matrix", "comment_inject", "xinclude_probe", "key_confusion", "relaystate_check"],
    stage: 4,
    tag: "saml.xsw",
    unorthodox: true,
    tradecraft: "XML Signature Wrapping breaks the assumption that a signed assertion is an unmodified assertion — comment injection in NameID logs you in as anyone@corp.",
  },
  {
    key: "passwords",
    name: "PasswordSprayAgent",
    version: "1.2.0",
    safetyClass: "data-touching",
    category: "credentials",
    states: ["corpus_align", "spray_calendar", "default_cred_matrix", "mfa_fatigue_sim", "roastable_check", "verify_readonly"],
    stage: 4,
    tag: "creds.spray",
    unorthodox: true,
    tradecraft: "One password, every account, business hours — spraying avoids lockouts, MFA-fatigue push bombing bypasses the second factor, and kerberoastable SPNs hand over service tickets offline.",
  },
  {
    key: "race",
    name: "RaceConditionAgent",
    version: "1.1.0",
    safetyClass: "data-touching",
    category: "logic",
    states: ["endpoint_select", "single_packet_sync", "contention_matrix", "window_widen", "overdraw_measure", "verify"],
    stage: 4,
    tag: "race.single-packet",
  },
  {
    key: "bizlogic",
    name: "BusinessLogicAgent",
    version: "1.0.2",
    safetyClass: "data-touching",
    category: "logic",
    states: ["flow_model", "state_jump_matrix", "currency_precision_probe", "negative_qty_matrix", "coupon_stack", "verify_impact"],
    stage: 4,
    tag: "logic.negative-qty",
  },
  {
    key: "timing",
    name: "TimingSideChannelAgent",
    version: "1.0.1",
    safetyClass: "read-only",
    category: "side-channel",
    states: ["baseline_sample", "safe_compare_oracle", "user_enum_delta", "jwt_existence_oracle", "cache_timing", "significance_test"],
    stage: 4,
    tag: "timing.oracle",
    unorthodox: true,
    tradecraft: "A 40ms difference in a string-comparison tells an attacker which usernames exist — timing oracles leak membership without a single error message.",
  },

  // ── Dynamic agents (dormant → spawn on runtime trigger) ───────────────────
  {
    key: "shadowapi",
    name: "ShadowAPIAgent",
    version: "1.0.0",
    safetyClass: "data-touching",
    category: "api",
    states: ["spec_diff", "version_brute", "deprecated_route_hunt", "mobile_only_surface", "debug_param_matrix", "admin_route_probe"],
    stage: 3,
    tag: "shadow.admin",
    dynamic: true,
    spawnOn: { agentKeys: ["crawler"] },
    spawnOnDesc: "CrawlerAgent mapped the route surface",
    unorthodox: true,
    tradecraft: "The OpenAPI spec lies by omission — attackers brute undocumented versions, mobile-only routes and debug parameters that never made it into the docs.",
  },
  {
    key: "fronting",
    name: "DomainFrontingAgent",
    version: "1.0.0",
    safetyClass: "read-only",
    category: "evasion",
    states: ["cdn_sni_map", "frontable_hunt", "divergence_test", "allowed_domain_pool", "egress_rotation_sim", "record_matrix"],
    stage: 3,
    tag: "front.cdn",
    dynamic: true,
    spawnOn: { agentKeys: ["fingerprint"] },
    spawnOnDesc: "FingerprintAgent classified a CDN/WAF in front of the origin",
    unorthodox: true,
    tradecraft: "When a WAF guards the front door, attackers ride the CDN itself — domain fronting splits SNI from Host so the block never sees the real destination.",
  },
  {
    key: "credreuse",
    name: "CredentialReuseAgent",
    version: "1.0.0",
    safetyClass: "data-touching",
    category: "credentials",
    states: ["harvest_intake", "surface_matrix", "vpn_replay", "sso_replay", "key_scope_replay", "verify_readonly"],
    stage: 4,
    tag: "reuse.vpn",
    dynamic: true,
    spawnOn: { agentKeys: ["secrets", "osint"] },
    spawnOnDesc: "SecretsHarvester or OSINT produced a harvested credential/key",
    unorthodox: true,
    tradecraft: "One leaked password is never one door — credential reuse testing walks every discovered surface (VPN, SSO, admin API) exactly like an initial-access broker does.",
  },
  {
    key: "pivot",
    name: "PivotAgent",
    version: "1.0.0",
    safetyClass: "read-only",
    category: "pivot",
    states: ["egress_map", "internal_sweep", "subnet_infer", "ad_recon_sim", "spn_roast_check", "lateral_surface_map"],
    stage: 5,
    tag: "pivot.ad",
    dynamic: true,
    spawnOn: { agentKeys: ["ssrf", "cloud"] },
    spawnOnDesc: "SSRF reached an internal network or the cloud agent touched the metadata plane",
    unorthodox: true,
    tradecraft: "The NodeZero move: an SSRF is not a finding, it is a doorway — pivot through it to map subnets, enumerate AD and find the internal-only admin panels.",
  },
  {
    key: "fusion",
    name: "FusionAgent",
    version: "1.0.0",
    safetyClass: "read-only",
    category: "fusion",
    states: ["pair_scan", "rule_match", "context_correlate", "compound_reason", "chain_poc_build", "emit_fused"],
    stage: 5,
    tag: "fusion.merge",
    dynamic: true,
    spawnOn: { minFindings: 2, distinctAgents: 2 },
    spawnOnDesc: "≥2 findings from ≥2 distinct agents are on the board",
    tradecraft: "Two findings that each mean nothing alone can compose into a critical threat — the fusion rulebook merges benign components into compound attack paths no single scanner would report.",
  },
];

export const AGENT_BY_KEY: Record<string, AgentSpec> = Object.fromEntries(AGENTS.map((a) => [a.key, a]));

export const MAX_STAGE = Math.max(...AGENTS.map((a) => a.stage)); // 5

export const DYNAMIC_AGENTS = AGENTS.filter((a) => a.dynamic);

/** quick profile = fast subset of the pipeline (static agents only). */
export const QUICK_PROFILE_AGENTS = ["recon", "fingerprint", "crawler", "ssrf", "injection", "correlator"];

/** Agents blocked by the "safe" policy tier (safetyClass === "data-touching"). */
export function isDataTouching(key: string): boolean {
  return AGENT_BY_KEY[key]?.safetyClass === "data-touching";
}
