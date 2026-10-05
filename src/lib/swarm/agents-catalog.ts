import type { AgentCatalogEntry } from "./types";

// ─── SwarmScan Agent Registry ────────────────────────────────────────────────
// Three families of agents across a 6-stage DAG (parallel within a stage,
// sequential across stages):
//   • classic     — the core pipeline (recon → evasion)
//   • unorthodox  — attacker tradecraft no textbook teaches (marked
//                   unorthodox: true with a tradecraft rationale)
//   • dynamic     — never statically planned; sit DORMANT until their runtime
//                   spawn trigger fires, then join the scan mid-flight
//                   (dynamic: true + spawnOnDesc trigger description)
// Mirrored by the scan-engine execution plane (mini-services/scan-engine/lib/agents.ts).

export const AGENTS_CATALOG: AgentCatalogEntry[] = [
  // ── Classic pipeline ──────────────────────────────────────────────────────
  {
    key: "recon",
    name: "ReconAgent",
    version: "2.1.3",
    safetyClass: "read-only",
    category: "recon",
    description:
      "Passive-first surface discovery: CT log aggregation, passive DNS with registrar-change detection, ASN peering, 40+ provider SaaS-takeover signature DB, permutation engine, and asset-delta emission for continuous mode.",
    states: [
      "passive_recon",
      "ct_logs",
      "passive_dns",
      "saas_takeover",
      "permutation",
      "active_diff",
      "asset_delta",
    ],
    consumes: ["target.scope"],
    emits: ["asset", "asset.delta", "handoff.takeover_surface"],
    stage: 0,
  },
  {
    key: "fingerprint",
    name: "FingerprintAgent",
    version: "2.4.0",
    safetyClass: "read-only",
    category: "recon",
    description:
      "Multi-signal fusion: ETag/served-by headers, static-asset byte hashing, favicon mmh2, JS chunk naming, error-page signatures. Mandatory WAF/CDN classification via behavioral probes feeding EvasionAgent. CVE mapping with dynamic verification.",
    states: [
      "signal_fusion",
      "static_hash",
      "favicon_hash",
      "waf_detect",
      "version_infer",
      "cve_map",
    ],
    consumes: ["asset"],
    emits: ["tech.signature", "waf.profile", "handoff.dbms_hint", "cve.candidate"],
    stage: 1,
  },
  {
    key: "crawler",
    name: "CrawlerAgent",
    version: "3.0.1",
    safetyClass: "read-only",
    category: "discovery",
    description:
      "JS-aware crawling with SWC AST parsing: route registrations, fetch/XHR template literals, postMessage handlers, GraphQL operations, leaked config objects. SPA headless-Chromium driving + parameter mining with response-diff oracle.",
    states: [
      "fetch_js",
      "ast_parse",
      "route_enum",
      "form_interact",
      "param_mine",
      "waterfall_capture",
    ],
    consumes: ["asset", "tech.signature"],
    emits: ["endpoint", "param", "write_surface"],
    stage: 2,
  },
  {
    key: "ssrf",
    name: "SSRFAgent",
    version: "1.9.2",
    safetyClass: "data-touching",
    category: "injection",
    description:
      "Full scheme matrix (gopher/dict/file/netdoc), IMDSv1/v2 with SSRF-to-SSRF token abuse, self-hosted DNS rebinder with TOCTOU verification, redirect-chain smugging, IPv6/decimal/octal canonicalization matrix, URL parser differentials.",
    states: [
      "scheme_matrix",
      "metadata_probe",
      "imds_v2",
      "dns_rebind",
      "redirect_chain",
      "verify",
    ],
    consumes: ["endpoint", "param"],
    emits: ["finding", "evidence.oob", "handoff.metadata_access"],
    stage: 2,
  },
  {
    key: "injection",
    name: "InjectionAgent",
    version: "1.4.0",
    safetyClass: "data-touching",
    category: "injection",
    description:
      "Context-grammar engine for SQLi/NoSQL/LDAP/XPath: payloads generated from (injection_point_class, dialect, encoding_chain) with stateful encoding-chain learning. 300+ DBMS error signatures, boolean-paired diffing, adaptive time-based contrast, OOB confirmation.",
    states: [
      "analyze_surface",
      "build_grammar",
      "probe_error",
      "probe_boolean",
      "probe_time",
      "probe_oob",
      "verify",
      "escalate",
    ],
    consumes: ["endpoint", "dbms_hint"],
    emits: ["finding", "evidence.oob", "handoff.dbms_identified"],
    stage: 3,
  },
  {
    key: "xss",
    name: "XSSAgent",
    version: "2.2.7",
    safetyClass: "data-touching",
    category: "client",
    description:
      "CDP-based DOM taint instrumentation patching sinks (innerHTML, eval, document.write, jQuery .html) and sources (location, postMessage, name). HTML5 tokenizer-level context parsing, mXSS serialization round-trip hunting, CSP evaluator, stored-XSS canary orchestration.",
    states: [
      "analyze_context",
      "dom_instrument",
      "probe_reflection",
      "probe_dom",
      "mxss_roundtrip",
      "csp_eval",
      "stored_check",
    ],
    consumes: ["endpoint", "param", "write_surface"],
    emits: ["finding", "evidence.dom_taint"],
    stage: 3,
  },
  {
    key: "fileops",
    name: "FileOpsAgent",
    version: "1.6.4",
    safetyClass: "data-touching",
    category: "files",
    description:
      "LFI filter-chain engine (php://filter chain generator), log-poisoning with session-file race, /proc/self/environ canaries, NTFS ADS + traversal normalization-differential matrix, polyglot uploads with fetch-back execution oracle.",
    states: [
      "wrapper_matrix",
      "filter_chain",
      "traversal_matrix",
      "upload_polyglot",
      "exec_oracle",
    ],
    consumes: ["endpoint", "param", "write_surface"],
    emits: ["finding", "evidence.oob"],
    stage: 3,
  },
  {
    key: "deser",
    name: "DeserializationAgent",
    version: "1.3.8",
    safetyClass: "data-touching",
    category: "injection",
    description:
      "Environment-dependent gadget-chain selection: JDK/library classpath inference from fingerprints, DNS-only first-stage gadgets for blind confirmation. Java ysoserial grammar, .NET ViewState oracle, Python pickle, PHP phpggc/phar, Ruby Marshal, node-serialize.",
    states: [
      "classpath_infer",
      "gadget_select",
      "dns_first_stage",
      "escalate",
      "verify",
    ],
    consumes: ["endpoint", "tech.signature"],
    emits: ["finding", "evidence.oob"],
    stage: 3,
  },
  {
    key: "auth",
    name: "AuthAgent",
    version: "2.0.5",
    safetyClass: "data-touching",
    category: "authz",
    description:
      "IDOR object-access matrix across ≥2 roles with framework-aware response-diff oracle, JWT suite (alg none, HS/RS confusion, kid injection, jku/x5u OOB), HTTP/2 single-packet race testing with binomial significance, session fixation/rotation, OAuth redirect_uri bypass matrix.",
    states: [
      "session_map",
      "idor_matrix",
      "jwt_probes",
      "race_test",
      "oauth_matrix",
      "session_verify",
    ],
    consumes: ["endpoint", "credential.role"],
    emits: ["finding", "handoff.role_escalation"],
    stage: 4,
  },
  {
    key: "api",
    name: "APIAgent",
    version: "1.8.0",
    safetyClass: "data-touching",
    category: "api",
    description:
      "Spec-driven OpenAPI coverage matrix with typed fuzzing, GraphQL introspection bypass variants + field-suggestion character-by-character oracle + alias-bomb batching, gRPC reflection fuzzing, mass-assignment field injection matrix.",
    states: [
      "spec_import",
      "coverage_matrix",
      "graphql_introspect",
      "field_suggest",
      "batch_probe",
      "mass_assign",
    ],
    consumes: ["endpoint", "tech.signature"],
    emits: ["finding", "api.contract"],
    stage: 4,
  },
  {
    key: "crypto",
    name: "CryptographyAgent",
    version: "1.5.1",
    safetyClass: "read-only",
    category: "crypto",
    description:
      "TLS full policy audit (protocol/cipher/curve/extension matrix, CT validation), Bleichenbacher-style adaptive oracle with caps, app-layer padding-oracle full exploitation within policy, JWT/JWE misuse, statistical entropy tests + PRNG-state recovery on session tokens.",
    states: [
      "tls_audit",
      "cert_chain",
      "padding_oracle",
      "jwt_crypto",
      "entropy_sample",
    ],
    consumes: ["asset", "tech.signature"],
    emits: ["finding", "tls.report"],
    stage: 4,
  },
  {
    key: "cloud",
    name: "CloudAgent",
    version: "1.7.2",
    safetyClass: "read-only",
    category: "cloud",
    description:
      "S3/GCS/Azure bucket enumeration with per-provider auth semantics, cloud-dangling takeover, IMDS credential handling with hash-only evidence (secrets never logged), read-only IAM simulate-principal-policy when operator creds supplied.",
    states: [
      "bucket_enum",
      "takeover_check",
      "imds_handle",
      "iam_sim",
    ],
    consumes: ["asset", "handoff.metadata_access"],
    emits: ["finding", "credential.shape"],
    stage: 4,
  },
  {
    key: "correlator",
    name: "CorrelatorAgent",
    version: "2.3.0",
    safetyClass: "read-only",
    category: "correlation",
    description:
      "The crown jewel: attack-graph model over findings with precondition/enablement edges, enumerating exploitation paths as a planning problem. Every chain gets a machine-verifiable PoC plan with approval gates between steps.",
    states: ["graph_build", "path_plan", "chain_score", "poc_plan"],
    consumes: ["finding", "credential.shape"],
    emits: ["attack.chain", "poc.plan"],
    stage: 5,
  },
  {
    key: "revisit",
    name: "RevisitAgent",
    version: "1.2.0",
    safetyClass: "read-only",
    category: "continuous",
    description:
      "Continuous-mode time-based re-testing queue: stored-XSS canary read-backs, takeover-surface rechecks, newly-issued-cert re-sweeps, JWT-key-rotation monitoring. Turns point-in-time scans into a continuous assessment platform.",
    states: [
      "queue_check",
      "canary_readback",
      "cert_resweep",
      "key_rotation_check",
    ],
    consumes: ["finding", "asset.delta"],
    emits: ["finding.recheck", "event.revisit"],
    stage: 5,
  },
  {
    key: "evasion",
    name: "EvasionAgent",
    version: "1.4.6",
    safetyClass: "read-only",
    category: "evasion",
    description:
      "Rule-based transformation grammar driven by WAF behavioral profiling: encoding chains, HTTP/2 continuation floods, case-mixing, dialect-aware comment placement, JSON key duplication for parser-differential WAFs. All bypass chains recorded in evidence.",
    states: ["waf_profile", "transform_grammar", "bypass_test", "record_chain"],
    consumes: ["waf.profile", "probe_feedback"],
    emits: ["transform.chain", "evidence.decision"],
    stage: 5,
  },

  // ── Unorthodox tradecraft (not taught — what real attackers run) ──────────
  {
    key: "osint",
    name: "OSINTAgent",
    version: "1.2.0",
    safetyClass: "read-only",
    category: "osint",
    description:
      "Human-layer recon: breach corpora joins (hash-only evidence), GH Archive commit-author mining, code-search dorks across public forges, Wayback diffing for deleted endpoints, employee email-pattern inference and job-posting tool-stack fingerprinting.",
    states: [
      "breach_corpus",
      "gharchive_diff",
      "code_search_dorks",
      "email_pattern",
      "wayback_diff",
      "harvest_score",
    ],
    consumes: ["target.scope"],
    emits: ["osint.corpus", "credential.shape"],
    stage: 0,
    unorthodox: true,
    tradecraft:
      "Real intrusions start with WHO you are, not what you expose — breach corpora, commit metadata and code-search dorks assemble a credential-targeting picture before a single packet is sent.",
  },
  {
    key: "edge",
    name: "EdgeDeviceAgent",
    version: "1.1.0",
    safetyClass: "data-touching",
    category: "perimeter",
    description:
      "Perimeter-appliance hunting: SSL-VPN/EDR/fingerprinting of Ivanti, Citrix, Fortinet, F5, Palo Alto with build-level banner differentials, pre-auth RCE chains (CVE-2024-21887, Citrix Bleed, FortiGate path traversal), session-file leak checks.",
    states: [
      "vpn_fingerprint",
      "banner_differential",
      "preauth_probe",
      "cve_chain_match",
      "session_leak_check",
      "verify",
    ],
    consumes: ["asset"],
    emits: ["finding", "edge.rce_chain"],
    stage: 1,
    unorthodox: true,
    tradecraft:
      "APTs don't scan web apps first — they mass-hunt SSL-VPN appliances for pre-auth RCE chains because the edge device IS the perimeter.",
  },
  {
    key: "smuggling",
    name: "RequestSmugglingAgent",
    version: "1.0.4",
    safetyClass: "data-touching",
    category: "smuggling",
    description:
      "Front/back-end parser-differential hunting: CL.TE / TE.CL / h2.CL desync probes with connection-close timing oracles, queue-poisoning confirmation, HTTP/2 downgrade smuggling, and prefix-capture verification against the next legitimate request.",
    states: [
      "differential_probe",
      "cl_te_desync",
      "te_cl_desync",
      "h2_downgrade",
      "queue_poison",
      "capture_verify",
    ],
    consumes: ["endpoint"],
    emits: ["finding", "evidence.smuggle_oracle"],
    stage: 2,
    unorthodox: true,
    tradecraft:
      "Front-end/back-end parser differentials (CL.TE, TE.CL, h2.CL) let an attacker smuggle a second request onto another user's connection — the closest thing to magic in web security.",
  },
  {
    key: "hostheader",
    name: "HostHeaderAgent",
    version: "1.0.2",
    safetyClass: "data-touching",
    category: "routing",
    description:
      "The Host header is routing state: vhost mapping, Host-override matrices, absolute-URI routing differentials, X-Forwarded-* chain confusion, password-reset link poisoning, and cache-key manipulation via forwarded hosts.",
    states: [
      "vhost_map",
      "host_override_matrix",
      "absolute_uri_probe",
      "x_forwarded_matrix",
      "reset_poison_check",
      "cache_key_probe",
    ],
    consumes: ["endpoint"],
    emits: ["finding", "routing.differential"],
    stage: 2,
    unorthodox: true,
    tradecraft:
      "The Host header is routing state — password-reset poisoning, cache-key manipulation and internal-vhost confusion turn a 'cosmetic' header into account takeover.",
  },
  {
    key: "gitrepo",
    name: "RepoLootAgent",
    version: "1.1.1",
    safetyClass: "read-only",
    category: "disclosure",
    description:
      "Exposed-VCS full exploitation: .git object recovery (loose + packed), packed-refs walking, deleted-secret history diffs, CI pipeline definition looting (GitHub Actions/GitLab CI), deployment key and registry credential extraction.",
    states: [
      "dotgit_check",
      "object_recovery",
      "packed_refs_walk",
      "history_diff",
      "config_loot",
      "ci_pipeline_map",
    ],
    consumes: ["asset"],
    emits: ["finding", "credential.shape"],
    stage: 2,
    unorthodox: true,
    tradecraft:
      "An exposed .git is not 'information disclosure' — it is the source tree, every secret ever committed, and the CI pipeline in one loot bag.",
  },
  {
    key: "secrets",
    name: "SecretsHarvesterAgent",
    version: "1.3.0",
    safetyClass: "read-only",
    category: "secrets",
    description:
      "Client-asset secret hunting: JS bundle entropy windows, sourcemap recovery with original-name mining, token shape classification (AWS/GCP/Stripe/Slack/JWT), read-only liveness probes against harvested keys, scope mapping without plaintext storage.",
    states: [
      "bundle_sweep",
      "entropy_window",
      "sourcemap_recover",
      "token_shape_classify",
      "key_liveness_probe",
      "scope_map",
    ],
    consumes: ["endpoint", "write_surface"],
    emits: ["finding", "credential.shape"],
    stage: 2,
    unorthodox: true,
    tradecraft:
      "Attackers grep JS bundles and sourcemaps for live keys before touching a login form — a staging key valid against production is the shortest path to the crown jewels.",
  },
  {
    key: "cachepoison",
    name: "CachePoisoningAgent",
    version: "1.0.3",
    safetyClass: "data-touching",
    category: "cache",
    description:
      "Shared-cache exploitation: cache-key inference via Age-header oracles, unkeyed-input hunting (X-Forwarded-*, X-Original-URL), fat-GET probing, poison-storage verification from a second client identity, cache-deception path matrices for PII leakage.",
    states: [
      "cache_key_infer",
      "unkeyed_input_hunt",
      "poison_probe",
      "fat_get_test",
      "deception_path_matrix",
      "stored_capture",
    ],
    consumes: ["endpoint", "waf.profile"],
    emits: ["finding", "evidence.cache_oracle"],
    stage: 3,
    unorthodox: true,
    tradecraft:
      "Unkeyed inputs poison the shared cache for every user; cache-deception paths make the cache serve another user's PII to you. No payload ever touches the app — the cache does the work.",
  },
  {
    key: "prototype",
    name: "PrototypePollutionAgent",
    version: "1.0.2",
    safetyClass: "data-touching",
    category: "client",
    description:
      "Prototype-pollution sink hunting: deep-merge gadget discovery (client + server), __proto__/constructor.prototype bypass matrices, gadget-chain selection (child_process, EJS/HBS render opts, jQuery extend), execution oracles with OOB confirmation.",
    states: [
      "merge_gadget_hunt",
      "proto_probe",
      "constructor_bypass",
      "gadget_chain_select",
      "exec_oracle",
      "verify",
    ],
    consumes: ["endpoint", "param"],
    emits: ["finding", "evidence.oob"],
    stage: 3,
    unorthodox: true,
    tradecraft:
      "Polluting Object.prototype is silent — but chained into RCE gadgets (child_process options, EJS render opts) it becomes pre-auth remote code execution.",
  },
  {
    key: "websocket",
    name: "WebSocketAgent",
    version: "1.0.1",
    safetyClass: "data-touching",
    category: "api",
    description:
      "WebSocket attack surface: upgrade capture, Origin-allowlist checking for CSWSH, message-protocol fuzzing, authentication replay across sockets, subprotocol confusion, and internal event-bus injection through unvalidated message parses.",
    states: [
      "upgrade_capture",
      "origin_check_matrix",
      "cswsh_probe",
      "message_fuzz",
      "auth_replay",
      "subprotocol_confuse",
    ],
    consumes: ["endpoint"],
    emits: ["finding"],
    stage: 3,
  },
  {
    key: "saml",
    name: "SamlAgent",
    version: "1.1.0",
    safetyClass: "data-touching",
    category: "authz",
    description:
      "Federated-auth exploitation: metadata parsing, full XSW variant matrix (8 wrappers), XML comment/entity injection in NameID, XInclude probing, key-confusion (RS↔HS) and RelayState open-redirect checks.",
    states: [
      "metadata_parse",
      "xsw_matrix",
      "comment_inject",
      "xinclude_probe",
      "key_confusion",
      "relaystate_check",
    ],
    consumes: ["endpoint"],
    emits: ["finding", "handoff.role_escalation"],
    stage: 4,
    unorthodox: true,
    tradecraft:
      "XML Signature Wrapping breaks the assumption that a signed assertion is an unmodified assertion — comment injection in NameID logs you in as anyone@corp.",
  },
  {
    key: "passwords",
    name: "PasswordSprayAgent",
    version: "1.2.0",
    safetyClass: "data-touching",
    category: "credentials",
    description:
      "Identity-plane attacks within policy: lockout-policy probing, business-hours spray calendars (one password, every account), default-credential matrices on admin surfaces, MFA-fatigue push simulation, kerberoastable SPN discovery.",
    states: [
      "corpus_align",
      "spray_calendar",
      "default_cred_matrix",
      "mfa_fatigue_sim",
      "roastable_check",
      "verify_readonly",
    ],
    consumes: ["osint.corpus", "credential.shape"],
    emits: ["finding"],
    stage: 4,
    unorthodox: true,
    tradecraft:
      "One password, every account, business hours — spraying avoids lockouts, MFA-fatigue push bombing bypasses the second factor, and kerberoastable SPNs hand over service tickets offline.",
  },
  {
    key: "race",
    name: "RaceConditionAgent",
    version: "1.1.0",
    safetyClass: "data-touching",
    category: "logic",
    description:
      "Concurrency-exploit specialist: HTTP/2 single-packet synchronization (last-byte jitter elimination), contention matrices over money/limit endpoints, race-window widening via layered requests, overdraw measurement with binomial significance, TOCTOU role-check windows.",
    states: [
      "endpoint_select",
      "single_packet_sync",
      "contention_matrix",
      "window_widen",
      "overdraw_measure",
      "verify",
    ],
    consumes: ["endpoint"],
    emits: ["finding", "evidence.timing"],
    stage: 4,
  },
  {
    key: "bizlogic",
    name: "BusinessLogicAgent",
    version: "1.0.2",
    safetyClass: "data-touching",
    category: "logic",
    description:
      "Workflow-model abuse: state-machine jumping (skip checkout steps), currency/precision tricks, negative-quantity and integer-overflow matrices, coupon/discount stacking, workflow-order inversion — the bug class no scanner can pattern-match.",
    states: [
      "flow_model",
      "state_jump_matrix",
      "currency_precision_probe",
      "negative_qty_matrix",
      "coupon_stack",
      "verify_impact",
    ],
    consumes: ["endpoint", "api.contract"],
    emits: ["finding"],
    stage: 4,
  },
  {
    key: "timing",
    name: "TimingSideChannelAgent",
    version: "1.0.1",
    safetyClass: "read-only",
    category: "side-channel",
    description:
      "Statistical timing oracles: constant-time-compare violations, user-enumeration deltas via bcrypt cost, JWT kid existence oracles, cache-timing on token lookups — all with Mann-Whitney/Welch significance testing over hundreds of rounds.",
    states: [
      "baseline_sample",
      "safe_compare_oracle",
      "user_enum_delta",
      "jwt_existence_oracle",
      "cache_timing",
      "significance_test",
    ],
    consumes: ["endpoint"],
    emits: ["finding", "evidence.timing"],
    stage: 4,
    unorthodox: true,
    tradecraft:
      "A 40ms difference in a string-comparison tells an attacker which usernames exist — timing oracles leak membership without a single error message.",
  },

  // ── Dynamic agents (dormant → spawn on runtime trigger) ───────────────────
  {
    key: "shadowapi",
    name: "ShadowAPIAgent",
    version: "1.0.0",
    safetyClass: "data-touching",
    category: "api",
    description:
      "Hunts the API surface the spec lies about: version brute-forcing beyond documented routes, deprecated-but-routed endpoints, mobile-only namespaces with older validation, debug parameters, and admin routes that never made it into OpenAPI.",
    states: [
      "spec_diff",
      "version_brute",
      "deprecated_route_hunt",
      "mobile_only_surface",
      "debug_param_matrix",
      "admin_route_probe",
    ],
    consumes: ["endpoint", "api.contract"],
    emits: ["finding", "api.shadow_route"],
    stage: 3,
    dynamic: true,
    spawnOnDesc: "CrawlerAgent mapped the route surface",
    unorthodox: true,
    tradecraft:
      "The OpenAPI spec lies by omission — attackers brute undocumented versions, mobile-only routes and debug parameters that never made it into the docs.",
  },
  {
    key: "fronting",
    name: "DomainFrontingAgent",
    version: "1.0.0",
    safetyClass: "read-only",
    category: "evasion",
    description:
      "CDN-abuse surface mapping: SNI/Host divergence testing on every edge, frontable-domain pool hunting, allowed-domain collateral discovery, egress-rotation feasibility from inside the network — the defender's view of domain-fronting exfiltration paths.",
    states: [
      "cdn_sni_map",
      "frontable_hunt",
      "divergence_test",
      "allowed_domain_pool",
      "egress_rotation_sim",
      "record_matrix",
    ],
    consumes: ["waf.profile"],
    emits: ["finding", "evasion.fronting_matrix"],
    stage: 3,
    dynamic: true,
    spawnOnDesc: "FingerprintAgent classified a CDN/WAF in front of the origin",
    unorthodox: true,
    tradecraft:
      "When a WAF guards the front door, attackers ride the CDN itself — domain fronting splits SNI from Host so the block never sees the real destination.",
  },
  {
    key: "credreuse",
    name: "CredentialReuseAgent",
    version: "1.0.0",
    safetyClass: "data-touching",
    category: "credentials",
    description:
      "Initial-access simulation: walks every harvested credential/key shape across every discovered surface (VPN, SSO, admin API, mail) exactly like an initial-access broker — read-only verification, immediate session drop, scope-escalation detection for environment-mislabeled keys.",
    states: [
      "harvest_intake",
      "surface_matrix",
      "vpn_replay",
      "sso_replay",
      "key_scope_replay",
      "verify_readonly",
    ],
    consumes: ["credential.shape", "osint.corpus"],
    emits: ["finding", "handoff.initial_access"],
    stage: 4,
    dynamic: true,
    spawnOnDesc: "SecretsHarvester or OSINT produced a harvested credential/key",
    unorthodox: true,
    tradecraft:
      "One leaked password is never one door — credential reuse testing walks every discovered surface (VPN, SSO, admin API) exactly like an initial-access broker does.",
  },
  {
    key: "pivot",
    name: "PivotAgent",
    version: "1.0.0",
    safetyClass: "read-only",
    category: "pivot",
    description:
      "The NodeZero move — turns an SSRF into a doorway: internal subnet sweeps through the pivot oracle, alive-host mapping, AD recon simulation (users/groups/SPNs via read-only LDAP shapes), internal-only admin panel discovery, lateral-movement surface graphing.",
    states: [
      "egress_map",
      "internal_sweep",
      "subnet_infer",
      "ad_recon_sim",
      "spn_roast_check",
      "lateral_surface_map",
    ],
    consumes: ["handoff.metadata_access", "evidence.oob"],
    emits: ["finding", "pivot.internal_map"],
    stage: 5,
    dynamic: true,
    spawnOnDesc: "SSRF reached an internal network or the cloud agent touched the metadata plane",
    unorthodox: true,
    tradecraft:
      "The NodeZero move: an SSRF is not a finding, it is a doorway — pivot through it to map subnets, enumerate AD and find the internal-only admin panels.",
  },
  {
    key: "fusion",
    name: "FusionAgent",
    version: "1.0.0",
    safetyClass: "read-only",
    category: "fusion",
    description:
      "Cross-finding composition reasoning: pairs and triples of individually-benign findings are matched against a fusion rulebook — two harmless components merge into a compound threat (constrained file read + log-path disclosure = RCE; smuggling primitive + unkeyed cache = mass poisoning). Fused findings carry decision evidence joining the WORM ledger.",
    states: [
      "pair_scan",
      "rule_match",
      "context_correlate",
      "compound_reason",
      "chain_poc_build",
      "emit_fused",
    ],
    consumes: ["finding"],
    emits: ["finding.fused", "evidence.decision"],
    stage: 5,
    dynamic: true,
    spawnOnDesc: "≥2 findings from ≥2 distinct agents are on the board",
    tradecraft:
      "Two findings that each mean nothing alone can compose into a critical threat — the fusion rulebook merges benign components into compound attack paths no single scanner would report.",
  },
];

export const AGENT_BY_KEY: Record<string, AgentCatalogEntry> = Object.fromEntries(
  AGENTS_CATALOG.map((a) => [a.key, a])
);

export const MAX_STAGE = Math.max(...AGENTS_CATALOG.map((a) => a.stage));

/** Static agents = selectable in a scan plan (dynamic ones spawn at runtime). */
export const STATIC_AGENT_KEYS: string[] = AGENTS_CATALOG.filter((a) => !a.dynamic).map((a) => a.key);

/** Dynamic agents = dormant until their runtime spawn trigger fires. */
export const DYNAMIC_AGENT_KEYS: string[] = AGENTS_CATALOG.filter((a) => a.dynamic).map((a) => a.key);

// ─── Cross-finding fusion rulebook (control-plane mirror) ────────────────────
// Mirrors mini-services/scan-engine/lib/findings.ts FUSION_RULES. Shown in the
// FusionAgent detail dialog — each rule fuses individually-benign components
// into a compound threat.

export interface FusionRuleView {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  requires: { agentKey: string; category: string; severityAtMost: string }[];
  description: string;
}

export const FUSION_RULES_VIEW: FusionRuleView[] = [
  {
    id: "fus-xss-waf",
    name: "WAF-protected reflected XSS — error-path reflection + inspection-scope gap compose",
    severity: "high",
    requires: [
      { agentKey: "fingerprint", category: "waf-profile", severityAtMost: "low" },
      { agentKey: "xss", category: "xss", severityAtMost: "low" },
    ],
    description:
      "A WAF inspection-scope profile is a hardening note; a 404-path reflection with no reached sink is a low finding. Composed: the reflection endpoint falls outside the WAF's inspection scope — the merged path is a working reflected XSS on a WAF-protected origin.",
  },
  {
    id: "fus-lfi-log",
    name: "Constrained file read + log-path disclosure = log-poisoning RCE",
    severity: "critical",
    requires: [
      { agentKey: "crawler", category: "verbose-surface", severityAtMost: "low" },
      { agentKey: "fileops", category: "lfi", severityAtMost: "low" },
    ],
    description:
      "An extension-constrained file read is low risk alone; a health endpoint leaking the log path is informational. Merged: the read covers the app's own access log, the User-Agent lands in it, and poisoning the log turns two harmless findings into unauthenticated RCE.",
  },
  {
    id: "fus-ssrf-imds",
    name: "SSRF oracle + metadata role disclosure = cloud credential capture path",
    severity: "critical",
    requires: [
      { agentKey: "ssrf", category: "ssrf-internal", severityAtMost: "low" },
      { agentKey: "cloud", category: "imds-info", severityAtMost: "low" },
    ],
    description:
      "An SSRF port oracle is a low finding; a metadata endpoint revealing only the role name is informational. Composed: the oracle proves the metadata route reachable, the role name pins the credentials URL — a complete credential-capture chain. An SSRF is a doorway, not a finding.",
  },
  {
    id: "fus-spray-corpus",
    name: "Employee corpus + absent lockout = targeted password spray",
    severity: "high",
    requires: [
      { agentKey: "osint", category: "osint-corpus", severityAtMost: "info" },
      { agentKey: "passwords", category: "no-lockout", severityAtMost: "low" },
    ],
    description:
      "An identity corpus is reconnaissance data; a missing lockout is a hardening gap. Merged: 214 addresses, known password shapes, zero lockout — the highest-probability initial-access vector in real intrusions, assembled from two non-exploitable findings.",
  },
  {
    id: "fus-smuggle-cache",
    name: "Smuggling primitive + unkeyed cache = mass response poisoning",
    severity: "critical",
    requires: [
      { agentKey: "smuggling", category: "smuggling-primitive", severityAtMost: "low" },
      { agentKey: "cachepoison", category: "cache-key", severityAtMost: "info" },
    ],
    description:
      "A timing signature suggesting parser disagreement proves nothing alone; an unkeyed cache header is a hygiene note. Composed: the smuggled prefix becomes the cached body for a popular path — account takeover at scale without attacking any single user.",
  },
  {
    id: "fus-reset-takeover",
    name: "Differential routing + reset enumeration = account-takeover chain",
    severity: "high",
    requires: [
      { agentKey: "hostheader", category: "routing-differential", severityAtMost: "low" },
      { agentKey: "auth", category: "user-enum", severityAtMost: "low" },
    ],
    description:
      "An absolute-URI routing differential is a parser quirk; reset response differential is a low info leak. Composed: reset links built from the attacker-controllable forwarded host on a URI-line-routed path, with the oracle naming exactly which users to target.",
  },
];
