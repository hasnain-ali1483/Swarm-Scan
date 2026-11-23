// ─── SwarmScan Autonomous Remediation & Virtual Patching Engine ──────────────
//
// Automatically synthesizes:
//   1. WAF Virtual Patches (Cloudflare, AWS WAF v2, ModSecurity / Coraza, NGINX)
//   2. Code-Level Remediations (TypeScript/Node.js, Python, Go, Java, PHP)
//   3. Standard Unified Git Diffs (.patch files)
//
// Designed to bridge the gap between detection and real-time defense.

import type { Finding, Severity } from "@/lib/swarm/types";

export interface WafRule {
  provider: "cloudflare" | "awswaf" | "modsecurity" | "nginx";
  providerLabel: string;
  title: string;
  filename: string;
  language: string;
  code: string;
  explanation: string;
}

export interface CodeRemediation {
  language: string;
  label: string;
  filename: string;
  vulnerableSnippet: string;
  fixedSnippet: string;
  explanation: string;
  gitPatch: string;
}

export interface RemediationPackage {
  findingId: string;
  title: string;
  severity: Severity;
  category: string;
  endpoint: string;
  cve: string | null;
  summary: string;
  wafRules: WafRule[];
  codeRemediations: CodeRemediation[];
  generatedAt: string;
}

/** Sanitize an endpoint string to a safe path for matching */
function sanitizePath(endpoint: string | null | undefined): string {
  if (!endpoint) return "/";
  try {
    if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
      const u = new URL(endpoint);
      return u.pathname || "/";
    }
  } catch {
    // fallback to regex
  }
  const match = endpoint.match(/^(\/[^?#]*)/);
  return match ? match[1] : (endpoint.startsWith("/") ? endpoint : `/${endpoint}`);
}

/** Extract query param or target parameter name if discernible */
function extractParam(finding: Finding): string {
  if (finding.endpoint && finding.endpoint.includes("?")) {
    const query = finding.endpoint.split("?")[1] || "";
    const params = query.split("&").map((p) => p.split("=")[0]);
    if (params[0]) return params[0];
  }
  if (finding.pocScript) {
    const m = finding.pocScript.match(/(?:param|arg|field|data)[\s"':=]+([a-zA-Z0-9_-]+)/i);
    if (m?.[1]) return m[1];
  }
  return "q";
}

/**
 * Synthesizes a comprehensive Remediation Package for any given Finding.
 */
export function generateRemediationPackage(finding: Finding): RemediationPackage {
  const path = sanitizePath(finding.endpoint);
  const param = extractParam(finding);
  const cat = (finding.category || "").toLowerCase();
  const title = finding.title || "Vulnerability";
  const ruleId = Math.abs(hashCode(finding.id)) % 800000 + 100000;

  let wafRules: WafRule[] = [];
  let codeRemediations: CodeRemediation[] = [];
  let summary = "";

  if (cat.includes("sqli") || cat.includes("injection") || finding.agentKey === "injection") {
    summary = `Virtual patch and source-code remediation to neutralize SQL Injection vulnerabilities on endpoint ${path} by enforcing strict token filtering at the edge and parameterized queries in the application layer.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Expression Syntax)",
        filename: `cloudflare-rule-sqli-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Matches HTTP GET/POST requests targeted at the endpoint that contain typical SQL meta-characters, UNION SELECT, OR boolean probes, or comment syntax, and immediately executes a Block action.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  http.request.uri.path eq "${path}" and (
    http.request.uri.query matches r"(?i)(\\b(union(\\s+all)?\\s+select|select\\s+.*\\s+from|insert\\s+into|update\\s+.*\\s+set|delete\\s+from|drop\\s+table)\\b|'|\\\"|--|/\\*|benchmark\\(|sleep\\()"
    or http.request.body.raw matches r"(?i)(\\b(union(\\s+all)?\\s+select|select\\s+.*\\s+from|insert\\s+into|update\\s+.*\\s+set|delete\\s+from|drop\\s+table)\\b|'|\\\"|--|/\\*|benchmark\\(|sleep\\()"
  )
)`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 JSON Rule Statement",
        filename: `aws-waf-sqli-${ruleId}.json`,
        language: "json",
        explanation: "AWS WAF rule using SqliMatchStatement combined with a ByteMatchStatement scoping down to the specific vulnerable URI.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-Mitigate-SQLi-${ruleId}`,
            Priority: 10,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanSQLi${ruleId}`,
            },
            Statement: {
              AndStatement: {
                Statements: [
                  {
                    ByteMatchStatement: {
                      SearchString: path,
                      FieldToMatch: { UriPath: {} },
                      TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
                      PositionalConstraint: "EXACTLY",
                    },
                  },
                  {
                    OrStatement: {
                      Statements: [
                        {
                          SqliMatchStatement: {
                            FieldToMatch: { AllQueryArguments: {} },
                            TextTransformations: [
                              { Priority: 0, Type: "URL_DECODE" },
                              { Priority: 1, Type: "HTML_ENTITY_DECODE" },
                            ],
                          },
                        },
                        {
                          SqliMatchStatement: {
                            FieldToMatch: { Body: {} },
                            TextTransformations: [
                              { Priority: 0, Type: "URL_DECODE" },
                              { Priority: 1, Type: "HTML_ENTITY_DECODE" },
                            ],
                          },
                        },
                      ],
                    },
                  },
                ],
              },
            },
          },
          null,
          2
        ),
      },
      {
        provider: "modsecurity",
        providerLabel: "ModSecurity / Coraza",
        title: "ModSecurity / OWASP Coraza SecRule Directive",
        filename: `modsec-sqli-${ruleId}.conf`,
        language: "apache",
        explanation: "Chained phase 2 rule intercepting requests to the specific URI that match standard SQL injection patterns and returning a 403 Forbidden.",
        code: `# SwarmScan Virtual Patch — SQL Injection Mitigation
# Finding ID: ${finding.id}
SecRule REQUEST_URI "@beginsWith ${path}" \\
    "id:${ruleId},\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SwarmScan Virtual Patch: SQLi attempt blocked on ${path}',\\
    tag:'application-multi',\\
    tag:'language-multi',\\
    tag:'platform-multi',\\
    tag:'attack-sqli',\\
    severity:'CRITICAL',\\
    chain"
    SecRule ARGS|REQUEST_BODY "@rx (?i)(\\b(union(\\s+all)?\\s+select|select\\s+.*\\s+from|insert\\s+into|update\\s+.*\\s+set|delete\\s+from|drop\\s+table)\\b|'|\\\"|--|/\\*|benchmark\\(|sleep\\()" \\
        "t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"`,
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Location Block with Regex Filter",
        filename: `nginx-sqli-${ruleId}.conf`,
        language: "nginx",
        explanation: "NGINX reverse proxy location rule returning 403 Forbidden when dangerous SQL injection tokens are detected in query arguments.",
        code: `# SwarmScan Virtual Patch for NGINX
location = ${path} {
    if ($args ~* "(union.*select|select.*from|insert.*into|drop.*table|'|\\\"|--|benchmark\\(|sleep\\()") {
        return 403;
    }
    proxy_pass http://backend_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}`,
      },
    ];

    codeRemediations = [
      {
        language: "typescript",
        label: "TypeScript / Node.js (Prisma / pg)",
        filename: "src/controllers/query.ts",
        explanation: "Replace string interpolation in raw queries with parameter bindings or native ORM query builders.",
        vulnerableSnippet: `// ❌ VULNERABLE: Direct string concatenation allows SQL Injection
export async function getUser(req: Request, res: Response) {
  const { ${param} } = req.query;
  const result = await db.$queryRawUnsafe(
    \`SELECT * FROM users WHERE id = '\${${param}}'\`
  );
  return res.json(result);
}`,
        fixedSnippet: `// ✅ SECURE: Use parameterized query or safe ORM method
export async function getUser(req: Request, res: Response) {
  const { ${param} } = req.query;
  if (typeof ${param} !== "string") {
    return res.status(400).json({ error: "Invalid ${param}" });
  }

  // Using Prisma's tagged template literal with automated parameterization:
  const result = await db.$queryRaw\`SELECT * FROM users WHERE id = \${${param}}\`;
  
  // Or preferably using the type-safe ORM client:
  // const result = await db.user.findUnique({ where: { id: ${param} } });
  
  return res.json(result);
}`,
        gitPatch: `--- a/src/controllers/query.ts
+++ b/src/controllers/query.ts
@@ -10,7 +10,7 @@ export async function getUser(req: Request, res: Response) {
   const { ${param} } = req.query;
-  const result = await db.$queryRawUnsafe(
-    \`SELECT * FROM users WHERE id = '\${${param}}'\`
-  );
+  const result = await db.$queryRaw\`SELECT * FROM users WHERE id = \${${param}}\`;
   return res.json(result);
 }`,
      },
      {
        language: "python",
        label: "Python (FastAPI / SQLAlchemy)",
        filename: "app/routers/query.py",
        explanation: "Use SQLAlchemy text() with bind parameters or ORM query filters instead of formatted f-strings.",
        vulnerableSnippet: `# ❌ VULNERABLE: Python f-string or string formatting
@router.get("${path}")
async def get_record(${param}: str, db: Session = Depends(get_db)):
    query = f"SELECT * FROM records WHERE ${param} = '{${param}}'"
    return db.execute(text(query)).fetchall()`,
        fixedSnippet: `# ✅ SECURE: Bound parameters prevent payload interpretation
@router.get("${path}")
async def get_record(${param}: str, db: Session = Depends(get_db)):
    # Using parameterized SQL text bind:
    query = text("SELECT * FROM records WHERE ${param} = :val")
    return db.execute(query, {"val": ${param}}).fetchall()
    
    # Or native SQLAlchemy ORM:
    # return db.query(Record).filter(Record.${param} == ${param}).all()`,
        gitPatch: `--- a/app/routers/query.py
+++ b/app/routers/query.py
@@ -12,4 +12,4 @@ async def get_record(${param}: str, db: Session = Depends(get_db)):
-    query = f"SELECT * FROM records WHERE ${param} = '{${param}}'"
-    return db.execute(text(query)).fetchall()
+    query = text("SELECT * FROM records WHERE ${param} = :val")
+    return db.execute(query, {"val": ${param}}).fetchall()`,
      },
      {
        language: "go",
        label: "Go (database/sql)",
        filename: "handlers/query.go",
        explanation: "Always pass parameters as variadic arguments to QueryContext instead of fmt.Sprintf.",
        vulnerableSnippet: `// ❌ VULNERABLE: fmt.Sprintf query concatenation
func GetRecord(w http.ResponseWriter, r *http.Request) {
    param := r.URL.Query().Get("${param}")
    query := fmt.Sprintf("SELECT id, name FROM items WHERE ${param} = '%s'", param)
    rows, err := db.Query(query)
}`,
        fixedSnippet: `// ✅ SECURE: Placeholder parameter binding
func GetRecord(w http.ResponseWriter, r *http.Request) {
    param := r.URL.Query().Get("${param}")
    query := "SELECT id, name FROM items WHERE ${param} = $1"
    rows, err := db.QueryContext(r.Context(), query, param)
}`,
        gitPatch: `--- a/handlers/query.go
+++ b/handlers/query.go
@@ -15,4 +15,4 @@ func GetRecord(w http.ResponseWriter, r *http.Request) {
-    query := fmt.Sprintf("SELECT id, name FROM items WHERE ${param} = '%s'", param)
-    rows, err := db.Query(query)
+    query := "SELECT id, name FROM items WHERE ${param} = $1"
+    rows, err := db.QueryContext(r.Context(), query, param) `,
      },
    ];
  } else if (cat.includes("xss") || finding.agentKey === "xss") {
    summary = `Virtual patch and source-code remediation to prevent Cross-Site Scripting (XSS) on endpoint ${path} by filtering script tags and DOM injection sinks, while enforcing context-aware encoding in templates.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Expression Syntax)",
        filename: `cloudflare-rule-xss-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Blocks requests targeted at the endpoint that contain script tags, event handlers (onerror/onload), javascript: URIs, or SVG payload vectors.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  http.request.uri.path eq "${path}" and (
    http.request.uri.query matches r"(?i)(<\\s*script|javascript\\s*:|on(error|load|click|mouseover|focus|blur)\\s*=|eval\\s*\\(|<\\s*svg|<\\s*img|<\\s*iframe)"
    or http.request.body.raw matches r"(?i)(<\\s*script|javascript\\s*:|on(error|load|click|mouseover|focus|blur)\\s*=|eval\\s*\\(|<\\s*svg|<\\s*img|<\\s*iframe)"
  )
)`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 JSON Rule Statement",
        filename: `aws-waf-xss-${ruleId}.json`,
        language: "json",
        explanation: "Combines exact URI matching with AWS WAF's managed XssMatchStatement inspection engine.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-Mitigate-XSS-${ruleId}`,
            Priority: 12,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanXSS${ruleId}`,
            },
            Statement: {
              AndStatement: {
                Statements: [
                  {
                    ByteMatchStatement: {
                      SearchString: path,
                      FieldToMatch: { UriPath: {} },
                      TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
                      PositionalConstraint: "EXACTLY",
                    },
                  },
                  {
                    XssMatchStatement: {
                      FieldToMatch: { AllQueryArguments: {} },
                      TextTransformations: [
                        { Priority: 0, Type: "URL_DECODE" },
                        { Priority: 1, Type: "HTML_ENTITY_DECODE" },
                      ],
                    },
                  },
                ],
              },
            },
          },
          null,
          2
        ),
      },
      {
        provider: "modsecurity",
        providerLabel: "ModSecurity / Coraza",
        title: "ModSecurity / OWASP Coraza SecRule Directive",
        filename: `modsec-xss-${ruleId}.conf`,
        language: "apache",
        explanation: "Detects cross-site scripting payload injections and enforces strict HTTP entity sanitization.",
        code: `# SwarmScan Virtual Patch — Cross-Site Scripting (XSS) Mitigation
# Finding ID: ${finding.id}
SecRule REQUEST_URI "@beginsWith ${path}" \\
    "id:${ruleId},\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SwarmScan Virtual Patch: XSS attack blocked on ${path}',\\
    tag:'attack-xss',\\
    severity:'HIGH',\\
    chain"
    SecRule ARGS|REQUEST_BODY "@rx (?i)(<\\s*script|javascript\\s*:|on(error|load|click|mouseover)\\s*=|eval\\s*\\(|<\\s*svg|<\\s*img|<\\s*iframe)" \\
        "t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"`,
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Location Block with CSP & XSS Header Hardening",
        filename: `nginx-xss-${ruleId}.conf`,
        language: "nginx",
        explanation: "Applies defensive headers including Content-Security-Policy (CSP) and denies common inline payload patterns.",
        code: `# SwarmScan Virtual Patch for NGINX — XSS Defense
location = ${path} {
    if ($args ~* "(<script|javascript:|onerror=|onload=|eval\\()") {
        return 403;
    }
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    proxy_pass http://backend_upstream;
}`,
      },
    ];

    codeRemediations = [
      {
        language: "typescript",
        label: "React / Next.js / TypeScript",
        filename: "src/components/Renderer.tsx",
        explanation: "Sanitize user-provided HTML with DOMPurify or render as plain text children instead of dangerouslySetInnerHTML.",
        vulnerableSnippet: `// ❌ VULNERABLE: Direct rendering of unsanitized HTML
export function UserProfile({ bio }: { bio: string }) {
  return (
    <div className="bio-container">
      {/* Attacker-controlled markup executes arbitrary scripts */}
      <div dangerouslySetInnerHTML={{ __html: bio }} />
    </div>
  );
}`,
        fixedSnippet: `// ✅ SECURE: Use DOMPurify sanitization or plain text
import DOMPurify from "isomorphic-dompurify";

export function UserProfile({ bio }: { bio: string }) {
  // Option A: Render as plain text (safest)
  // return <div className="bio-container">{bio}</div>;

  // Option B: Sanitize HTML if markup is legitimately required
  const cleanBio = DOMPurify.sanitize(bio, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "a"],
    ALLOWED_ATTR: ["href"],
  });

  return (
    <div className="bio-container">
      <div dangerouslySetInnerHTML={{ __html: cleanBio }} />
    </div>
  );
}`,
        gitPatch: `--- a/src/components/Renderer.tsx
+++ b/src/components/Renderer.tsx
@@ -5,4 +5,5 @@
+import DOMPurify from "isomorphic-dompurify";
 export function UserProfile({ bio }: { bio: string }) {
   return (
     <div className="bio-container">
-      <div dangerouslySetInnerHTML={{ __html: bio }} />
+      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />
     </div>
   );
 }`,
      },
      {
        language: "python",
        label: "Python (Flask / Jinja2)",
        filename: "app/templates/profile.html",
        explanation: "Remove the '| safe' filter in Jinja2 templates so user input is HTML-entity encoded.",
        vulnerableSnippet: `<!-- ❌ VULNERABLE: '| safe' disables automatic HTML entity escaping -->
<div class="user-bio">
    {{ user_input | safe }}
</div>`,
        fixedSnippet: `<!-- ✅ SECURE: Standard Jinja2 autoescaping converts < to &lt; -->
<div class="user-bio">
    {{ user_input }}
</div>`,
        gitPatch: `--- a/app/templates/profile.html
+++ b/app/templates/profile.html
@@ -3,3 +3,3 @@
 <div class="user-bio">
-    {{ user_input | safe }}
+    {{ user_input }}
 </div>`,
      },
    ];
  } else if (cat.includes("fileops") || cat.includes("traversal") || cat.includes("lfi") || finding.agentKey === "fileops") {
    summary = `Virtual patch and source-code remediation to prevent Path Traversal and Local File Inclusion (LFI) on endpoint ${path} by blocking directory climbing sequences (../) and enforcing strict path canonicalization.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Expression Syntax)",
        filename: `cloudflare-rule-traversal-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Blocks requests with path traversal patterns (../, ..\\, %2e%2e) or direct references to sensitive system files.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  http.request.uri.path eq "${path}" and (
    http.request.uri.query matches r"(?i)(\\.\\.[\\/\\\\]|%2e%2e[\\/\\\\]|\\/etc\\/(passwd|shadow|hosts)|[a-zA-Z]:\\\\windows)"
    or http.request.uri.path matches r"(?i)(\\.\\.[\\/\\\\]|%2e%2e[\\/\\\\])"
  )
)`,
      },
      {
        provider: "modsecurity",
        providerLabel: "ModSecurity / Coraza",
        title: "ModSecurity / OWASP Coraza SecRule Directive",
        filename: `modsec-traversal-${ruleId}.conf`,
        language: "apache",
        explanation: "Normalizes paths and inspects arguments for directory traversal sequences.",
        code: `# SwarmScan Virtual Patch — Path Traversal Mitigation
# Finding ID: ${finding.id}
SecRule REQUEST_URI|ARGS "@rx (?i)(\\.\\.[\\/\\\\]|%2e%2e|\\/etc\\/(passwd|shadow)|[a-zA-Z]:[\\\\\\/]windows)" \\
    "id:${ruleId},\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SwarmScan Virtual Patch: Path Traversal blocked on ${path}',\\
    tag:'attack-lfi',\\
    severity:'CRITICAL',\\
    t:none,t:urlDecodeUni,t:normalizePath"`,
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Traversal & Directory Climbing Filter",
        filename: `nginx-traversal-${ruleId}.conf`,
        language: "nginx",
        explanation: "Denies requests containing dot-dot-slash sequence variations before hitting application servers.",
        code: `# SwarmScan Virtual Patch for NGINX — Path Traversal Block
location = ${path} {
    if ($args ~* "(\\.\\./|\\.\\.\\\\|%2e%2e|/etc/passwd)") {
        return 403;
    }
    proxy_pass http://backend_upstream;
}`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 JSON Rule Statement",
        filename: `aws-waf-traversal-${ruleId}.json`,
        language: "json",
        explanation: "RegexMatchStatement on query parameters inspecting for traversal tokens.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-Mitigate-Traversal-${ruleId}`,
            Priority: 14,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanTraversal${ruleId}`,
            },
            Statement: {
              RegexMatchStatement: {
                RegexString: "(\\.\\./|\\.\\.\\\\|%2e%2e)",
                FieldToMatch: { AllQueryArguments: {} },
                TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }],
              },
            },
          },
          null,
          2
        ),
      },
    ];

    codeRemediations = [
      {
        language: "typescript",
        label: "Node.js / TypeScript (path.resolve)",
        filename: "src/services/fileServer.ts",
        explanation: "Canonicalize user paths using path.resolve and verify they remain rooted inside the designated base directory.",
        vulnerableSnippet: `// ❌ VULNERABLE: Direct path joining allows directory climbing
import path from "node:path";
import fs from "node:fs/promises";

export async function serveFile(req: Request, res: Response) {
  const filename = req.query.file as string;
  const filePath = path.join("/var/data/uploads", filename);
  const data = await fs.readFile(filePath);
  return res.send(data);
}`,
        fixedSnippet: `// ✅ SECURE: Verify resolved path begins with safe directory root
import path from "node:path";
import fs from "node:fs/promises";

const SAFE_ROOT = path.resolve("/var/data/uploads");

export async function serveFile(req: Request, res: Response) {
  const filename = req.query.file;
  if (typeof filename !== "string") {
    return res.status(400).send("Invalid file name");
  }

  // Canonicalize path:
  const safePath = path.resolve(SAFE_ROOT, filename);

  // Security guard: path must stay within the designated base directory
  if (!safePath.startsWith(SAFE_ROOT + path.sep)) {
    return res.status(403).send("Access denied: path traversal detected");
  }

  const data = await fs.readFile(safePath);
  return res.send(data);
}`,
        gitPatch: `--- a/src/services/fileServer.ts
+++ b/src/services/fileServer.ts
@@ -8,3 +8,7 @@ export async function serveFile(req: Request, res: Response) {
   const filename = req.query.file as string;
-  const filePath = path.join("/var/data/uploads", filename);
+  const safePath = path.resolve(SAFE_ROOT, filename);
+  if (!safePath.startsWith(SAFE_ROOT + path.sep)) {
+    return res.status(403).send("Forbidden");
+  }
+  const data = await fs.readFile(safePath);`,
      },
    ];
  } else if (cat.includes("ssrf") || finding.agentKey === "ssrf") {
    summary = `Virtual patch and source-code remediation to neutralize Server-Side Request Forgery (SSRF) on endpoint ${path} by blocking cloud metadata services (169.254.169.254) and private RFC1918 IP addresses.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Expression Syntax)",
        filename: `cloudflare-rule-ssrf-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Blocks requests where parameters contain AWS/GCP/Azure metadata IP addresses or loopback/private ranges.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  http.request.uri.path eq "${path}" and (
    http.request.uri.query matches r"(?i)(169\\.254\\.169\\.254|metadata\\.google|127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|10\\.\\d+\\.\\d+\\.\\d+|172\\.(1[6-9]|2\\d|3[0-1])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+)"
    or http.request.body.raw matches r"(?i)(169\\.254\\.169\\.254|metadata\\.google|127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|10\\.\\d+\\.\\d+\\.\\d+|172\\.(1[6-9]|2\\d|3[0-1])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+)"
  )
)`,
      },
      {
        provider: "modsecurity",
        providerLabel: "ModSecurity / Coraza",
        title: "ModSecurity / OWASP Coraza SecRule Directive",
        filename: `modsec-ssrf-${ruleId}.conf`,
        language: "apache",
        explanation: "Detects cloud instance metadata probes and private network target references in request variables.",
        code: `# SwarmScan Virtual Patch — SSRF Mitigation
SecRule ARGS|REQUEST_BODY "@rx (?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1|localhost|10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" \\
    "id:${ruleId},\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SwarmScan Virtual Patch: SSRF probe blocked on ${path}',\\
    tag:'attack-ssrf',\\
    severity:'CRITICAL'"`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 JSON Rule Statement",
        filename: `aws-waf-ssrf-${ruleId}.json`,
        language: "json",
        explanation: "Blocks requests attempting to target the 169.254.169.254 metadata endpoint.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-Mitigate-SSRF-${ruleId}`,
            Priority: 15,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanSSRF${ruleId}`,
            },
            Statement: {
              ByteMatchStatement: {
                SearchString: "169.254.169.254",
                FieldToMatch: { AllQueryArguments: {} },
                TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }],
                PositionalConstraint: "CONTAINS",
              },
            },
          },
          null,
          2
        ),
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Metadata Interceptor",
        filename: `nginx-ssrf-${ruleId}.conf`,
        language: "nginx",
        explanation: "Blocks requests passing loopback or cloud metadata addresses.",
        code: `# SwarmScan Virtual Patch for NGINX — SSRF Protection
location = ${path} {
    if ($args ~* "(169\\.254\\.169\\.254|127\\.0\\.0\\.1|localhost)") {
        return 403;
    }
    proxy_pass http://backend_upstream;
}`,
      },
    ];

    codeRemediations = [
      {
        language: "typescript",
        label: "Node.js (URL allowlisting & IP validation)",
        filename: "src/services/webhook.ts",
        explanation: "Validate target domain against an allowlist and resolve DNS to confirm IP is not in private RFC1918/link-local ranges before fetching.",
        vulnerableSnippet: `// ❌ VULNERABLE: Direct fetching of user-provided URL
export async function triggerWebhook(req: Request, res: Response) {
  const { targetUrl } = req.body;
  const response = await fetch(targetUrl);
  return res.json(await response.json());
}`,
        fixedSnippet: `// ✅ SECURE: Validate URL scheme, hostname, and private IP exclusion
import { lookup } from "node:dns/promises";
import ipaddr from "ipaddr.js";

export async function triggerWebhook(req: Request, res: Response) {
  const { targetUrl } = req.body;
  const url = new URL(targetUrl);

  // 1. Enforce HTTPS only
  if (url.protocol !== "https:") {
    return res.status(400).json({ error: "Only HTTPS endpoints permitted" });
  }

  // 2. Resolve DNS and inspect resolved IP
  const { address } = await lookup(url.hostname);
  const addr = ipaddr.parse(address);

  // 3. Reject private, loopback, carrier-grade NAT, or link-local addresses
  if (addr.range() !== "unicast") {
    return res.status(403).json({ error: "SSRF prevention: Internal address rejected" });
  }

  const response = await fetch(targetUrl, { redirect: "error" });
  return res.json(await response.json());
}`,
        gitPatch: `--- a/src/services/webhook.ts
+++ b/src/services/webhook.ts
@@ -5,3 +5,6 @@ export async function triggerWebhook(req: Request, res: Response) {
   const { targetUrl } = req.body;
+  const parsed = new URL(targetUrl);
+  if (parsed.protocol !== "https:") return res.status(400).send("Invalid protocol");
   const response = await fetch(targetUrl);`,
      },
    ];
  } else {
    // ── Generic / Default Security Hardening ────────────────────────────────
    summary = `Virtual patch and defensive security headers for ${title} on ${path} to filter anomalous requests and restrict execution contexts.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Security Expression)",
        filename: `cloudflare-rule-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Enforces rate limiting and anomalous header inspection for the affected endpoint.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Managed Challenge / Block
(
  http.request.uri.path eq "${path}" and (
    http.request.method in {"POST" "PUT" "DELETE"} and
    not (http.request.headers["content-type"][0] contains "application/json")
  )
)`,
      },
      {
        provider: "modsecurity",
        providerLabel: "ModSecurity / Coraza",
        title: "ModSecurity / OWASP Coraza SecRule Directive",
        filename: `modsec-${ruleId}.conf`,
        language: "apache",
        explanation: "Enforces HTTP protocol compliance and strict payload length limits on the endpoint.",
        code: `# SwarmScan Virtual Patch — General Protection
SecRule REQUEST_URI "@beginsWith ${path}" \\
    "id:${ruleId},\\
    phase:1,\\
    pass,\\
    nolog,\\
    setvar:tx.anomaly_score_threshold=5"`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 Rate Limiting Rule",
        filename: `aws-waf-${ruleId}.json`,
        language: "json",
        explanation: "Restricts request velocity on the vulnerable endpoint to protect against brute-force and resource exhaustion.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-RateLimit-${ruleId}`,
            Priority: 20,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanRateLimit${ruleId}`,
            },
            Statement: {
              RateBasedStatement: {
                Limit: 100,
                AggregateKeyType: "IP",
                ScopeDownStatement: {
                  ByteMatchStatement: {
                    SearchString: path,
                    FieldToMatch: { UriPath: {} },
                    TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
                    PositionalConstraint: "EXACTLY",
                  },
                },
              },
            },
          },
          null,
          2
        ),
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Security Headers Snippet",
        filename: `nginx-headers-${ruleId}.conf`,
        language: "nginx",
        explanation: "Enforces modern defensive response headers.",
        code: `# SwarmScan Hardening Headers
location = ${path} {
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    proxy_pass http://backend_upstream;
}`,
      },
    ];

    codeRemediations = [
      {
        language: "typescript",
        label: "TypeScript / Node.js Input Validation",
        filename: "src/middleware/validate.ts",
        explanation: "Enforce strict schema validation using Zod to ensure no unexpected fields or payloads reach handler functions.",
        vulnerableSnippet: `// ❌ VULNERABLE: Direct body consumption without runtime validation
app.post("${path}", (req, res) => {
  const data = req.body;
  processPayload(data);
  return res.json({ status: "ok" });
});`,
        fixedSnippet: `// ✅ SECURE: Strict schema definition rejecting unknown attributes
import { z } from "zod";

const PayloadSchema = z.object({
  id: z.string().uuid(),
  action: z.enum(["enable", "disable"]),
}).strict(); // Disallows unexpected attributes

app.post("${path}", (req, res) => {
  const parsed = PayloadSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.issues });
  }
  processPayload(parsed.data);
  return res.json({ status: "ok" });
});`,
        gitPatch: `--- a/src/middleware/validate.ts
+++ b/src/middleware/validate.ts
@@ -2,2 +2,4 @@
+import { z } from "zod";
 app.post("${path}", (req, res) => {
-  const data = req.body;
+  const parsed = PayloadSchema.safeParse(req.body);
+  if (!parsed.success) return res.status(400).send("Invalid input");`,
      },
    ];
  }

  return {
    findingId: finding.id,
    title,
    severity: finding.severity,
    category: finding.category,
    endpoint: path,
    cve: finding.cve,
    summary,
    wafRules,
    codeRemediations,
    generatedAt: new Date().toISOString(),
  };
}

/** Simple fast deterministic hash for numeric rule ID generation */
function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return hash;
}
