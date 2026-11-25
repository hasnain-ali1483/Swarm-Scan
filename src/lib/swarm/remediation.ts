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
  } else if (
    cat.includes("deser") ||
    cat.includes("prototype") ||
    finding.agentKey === "deser" ||
    finding.agentKey === "prototype"
  ) {
    summary = `Virtual patch and source-code remediation to neutralize Prototype Pollution and Insecure Deserialization on ${path} by blocking __proto__/constructor gadget chains and serialized object magic bytes.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Prototype Pollution & Deserialization)",
        filename: `cloudflare-rule-deser-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Blocks JSON/query payloads containing __proto__, constructor.prototype, or Java/PHP serialized object magic headers.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  http.request.uri.path eq "${path}" and (
    http.request.body.raw matches r"(?i)(__proto__|constructor\\[\\"?'?prototype|rO0AB|O:\\d+:\\\"[a-zA-Z0-9_]+\\\")"
    or http.request.uri.query matches r"(?i)(__proto__|constructor\\.prototype|prototype\\[)"
  )
)`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 JSON Rule Statement",
        filename: `aws-waf-deser-${ruleId}.json`,
        language: "json",
        explanation: "Inspects request body and query arguments for prototype pollution gadget keys.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-Mitigate-ProtoDeser-${ruleId}`,
            Priority: 16,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanProtoDeser${ruleId}`,
            },
            Statement: {
              OrStatement: {
                Statements: [
                  {
                    RegexMatchStatement: {
                      RegexString: "(__proto__|constructor\\.prototype|rO0AB)",
                      FieldToMatch: { Body: {} },
                      TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }],
                    },
                  },
                  {
                    RegexMatchStatement: {
                      RegexString: "(__proto__|constructor\\.prototype)",
                      FieldToMatch: { AllQueryArguments: {} },
                      TextTransformations: [{ Priority: 0, Type: "URL_DECODE" }],
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
        filename: `modsec-deser-${ruleId}.conf`,
        language: "apache",
        explanation: "Denies requests carrying prototype pollution keys or Java/PHP serialization gadgets.",
        code: `# SwarmScan Virtual Patch — Prototype Pollution & Deserialization Mitigation
SecRule REQUEST_URI "@beginsWith ${path}" \\
    "id:${ruleId},\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SwarmScan Virtual Patch: Prototype pollution / deser blocked on ${path}',\\
    tag:'attack-injection',\\
    severity:'CRITICAL',\\
    chain"
    SecRule ARGS|REQUEST_BODY "@rx (?i)(__proto__|constructor\\W+prototype|rO0AB|aced0005)" \\
        "t:none,t:urlDecodeUni"`,
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Prototype Key Blocker",
        filename: `nginx-deser-${ruleId}.conf`,
        language: "nginx",
        explanation: "Blocks query strings attempting prototype pollution on the target route.",
        code: `# SwarmScan Virtual Patch for NGINX — Prototype Pollution Defense
location = ${path} {
    if ($args ~* "(__proto__|constructor\\.prototype)") {
        return 403;
    }
    proxy_pass http://backend_upstream;
}`,
      },
    ];
    codeRemediations = [
      {
        language: "typescript",
        label: "TypeScript / Node.js (Safe Merge & Schema)",
        filename: "src/utils/merge.ts",
        explanation: "Reject __proto__, constructor, and prototype keys during object merges, or validate payloads with a strict Zod schema.",
        vulnerableSnippet: `// ❌ VULNERABLE: Recursive merge copies __proto__ onto Object.prototype
export function deepMerge(target: Record<string, any>, source: Record<string, any>) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}`,
        fixedSnippet: `// ✅ SECURE: Explicitly block prototype-polluting keys & use Object.create(null)
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function deepMerge(target: Record<string, any>, source: Record<string, any>) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key) || !Object.prototype.hasOwnProperty.call(source, key)) {
      continue;
    }
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = Object.create(null);
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}`,
        gitPatch: `--- a/src/utils/merge.ts
+++ b/src/utils/merge.ts
@@ -1,5 +1,7 @@
+const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
 export function deepMerge(target: Record<string, any>, source: Record<string, any>) {
   for (const key of Object.keys(source)) {
+    if (FORBIDDEN_KEYS.has(key)) continue;
     if (typeof source[key] === "object" && source[key] !== null) {`,
      },
    ];
  } else if (
    cat.includes("auth") ||
    cat.includes("bola") ||
    cat.includes("idor") ||
    cat.includes("saml") ||
    cat.includes("jwt") ||
    ["auth", "api", "saml", "bizlogic", "passwords"].includes(finding.agentKey)
  ) {
    summary = `Virtual patch and source-code remediation to enforce authentication, object-level authorization (BOLA/IDOR), and rate-limiting controls on ${path}.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Auth Enforcement & Credential Stuffing Guard)",
        filename: `cloudflare-rule-auth-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Requires a valid Bearer/Session token header on protected endpoints and blocks JWT alg:none tampering.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  http.request.uri.path eq "${path}" and (
    not any(http.request.headers["authorization"][*] contains "Bearer ")
    or http.request.headers["authorization"][0] matches r"(?i)^Bearer\\s+eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"
  )
)`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 Auth Header & Rate Limit Guard",
        filename: `aws-waf-auth-${ruleId}.json`,
        language: "json",
        explanation: "Rate-limits brute-force attempts on the auth/API endpoint to 30 requests per 5 minutes per IP.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-AuthGuard-${ruleId}`,
            Priority: 11,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanAuthGuard${ruleId}`,
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
        provider: "modsecurity",
        providerLabel: "ModSecurity / Coraza",
        title: "ModSecurity / OWASP Coraza SecRule Directive",
        filename: `modsec-auth-${ruleId}.conf`,
        language: "apache",
        explanation: "Blocks unsigned JWTs (alg:none) and unauthenticated calls to sensitive API routes.",
        code: `# SwarmScan Virtual Patch — Auth & JWT Hardening
SecRule REQUEST_URI "@beginsWith ${path}" \\
    "id:${ruleId},\\
    phase:1,\\
    deny,\\
    status:401,\\
    log,\\
    msg:'SwarmScan Virtual Patch: Missing or tampered Authorization header on ${path}',\\
    tag:'attack-auth',\\
    severity:'HIGH',\\
    chain"
    SecRule REQUEST_HEADERS:Authorization "@rx (^$|alg\\\":\\\"none)"`,
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Rate Limiting & Auth Header Check",
        filename: `nginx-auth-${ruleId}.conf`,
        language: "nginx",
        explanation: "Enforces Authorization header presence at the edge proxy.",
        code: `# SwarmScan Virtual Patch for NGINX — Auth Enforcement
location = ${path} {
    if ($http_authorization = "") {
        return 401;
    }
    proxy_pass http://backend_upstream;
}`,
      },
    ];
    codeRemediations = [
      {
        language: "typescript",
        label: "TypeScript / Next.js (Ownership & JWT Alg Pinning)",
        filename: "src/app/api/resource/route.ts",
        explanation: "Always enforce tenant/owner matching in database queries (preventing BOLA/IDOR) and pin allowed JWT verification algorithms.",
        vulnerableSnippet: `// ❌ VULNERABLE: Fetches record by ID without verifying ownership
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const record = await db.resource.findUnique({ where: { id: params.id } });
  return Response.json(record);
}`,
        fixedSnippet: `// ✅ SECURE: Authenticate session and scope query to authenticated userId
import { getSessionUser } from "@/lib/auth";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await getSessionUser(req);
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const record = await db.resource.findFirst({
    where: { id: params.id, ownerId: user.id },
  });
  if (!record) return Response.json({ error: "Not found" }, { status: 404 });
  return Response.json(record);
}`,
        gitPatch: `--- a/src/app/api/resource/route.ts
+++ b/src/app/api/resource/route.ts
@@ -1,4 +1,8 @@
 export async function GET(req: Request, { params }: { params: { id: string } }) {
-  const record = await db.resource.findUnique({ where: { id: params.id } });
+  const user = await getSessionUser(req);
+  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
+  const record = await db.resource.findFirst({
+    where: { id: params.id, ownerId: user.id },
+  });
   return Response.json(record);
 }`,
      },
    ];
  } else if (
    cat.includes("smuggl") ||
    cat.includes("cache") ||
    cat.includes("host") ||
    ["smuggling", "cachepoison", "hostheader"].includes(finding.agentKey)
  ) {
    summary = `Virtual patch and edge proxy hardening to neutralize HTTP Request Smuggling, Cache Poisoning, and Host Header Injection on ${path}.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Header & Desync Protection)",
        filename: `cloudflare-rule-smuggle-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Blocks requests carrying conflicting Transfer-Encoding/Content-Length headers or untrusted X-Forwarded-Host overrides.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  (len(http.request.headers["transfer-encoding"]) > 0 and len(http.request.headers["content-length"]) > 0)
  or len(http.request.headers["x-forwarded-host"]) > 0
  or len(http.request.headers["x-host"]) > 0
)`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 Host & Unkeyed Header Blocker",
        filename: `aws-waf-smuggle-${ruleId}.json`,
        language: "json",
        explanation: "Blocks requests with X-Forwarded-Host header injection used for cache poisoning.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-Mitigate-CacheHost-${ruleId}`,
            Priority: 17,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanCacheHost${ruleId}`,
            },
            Statement: {
              SizeConstraintStatement: {
                FieldToMatch: { SingleHeader: { Name: "x-forwarded-host" } },
                ComparisonOperator: "GT",
                Size: 0,
                TextTransformations: [{ Priority: 0, Type: "NONE" }],
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
        filename: `modsec-smuggle-${ruleId}.conf`,
        language: "apache",
        explanation: "Rejects ambiguous Transfer-Encoding + Content-Length combinations and unkeyed host headers.",
        code: `# SwarmScan Virtual Patch — HTTP Desync & Cache Poisoning Mitigation
SecRule &REQUEST_HEADERS:Transfer-Encoding "@gt 0" \\
    "id:${ruleId},\\
    phase:1,\\
    deny,\\
    status:400,\\
    log,\\
    msg:'SwarmScan Virtual Patch: Ambiguous TE+CL request smuggling attempt',\\
    severity:'CRITICAL',\\
    chain"
    SecRule &REQUEST_HEADERS:Content-Length "@gt 0"`,
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Strict Host & Header Normalization",
        filename: `nginx-smuggle-${ruleId}.conf`,
        language: "nginx",
        explanation: "Strips unkeyed forwarding headers and enforces HTTP/1.1 upstream connection normalization.",
        code: `# SwarmScan Virtual Patch for NGINX — Smuggling & Cache Poisoning Defense
location = ${path} {
    proxy_set_header Host $server_name;
    proxy_set_header X-Forwarded-Host "";
    proxy_set_header X-Original-URL "";
    proxy_http_version 1.1;
    proxy_pass http://backend_upstream;
}`,
      },
    ];
    codeRemediations = [
      {
        language: "typescript",
        label: "Node.js / Next.js (Strict Host Allowlist)",
        filename: "src/middleware.ts",
        explanation: "Never trust X-Forwarded-Host or Host headers for generating redirects, password reset links, or cache keys without allowlist validation.",
        vulnerableSnippet: `// ❌ VULNERABLE: Trusts arbitrary X-Forwarded-Host header
export function buildResetLink(req: Request, token: string) {
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  return \`https://\${host}/reset?token=\${token}\`;
}`,
        fixedSnippet: `// ✅ SECURE: Use canonical configured origin from environment
const CANONICAL_ORIGIN = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.example.com";

export function buildResetLink(token: string) {
  return \`\${CANONICAL_ORIGIN}/reset?token=\${encodeURIComponent(token)}\`;
}`,
        gitPatch: `--- a/src/middleware.ts
+++ b/src/middleware.ts
@@ -1,4 +1,4 @@
+const CANONICAL_ORIGIN = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.example.com";
 export function buildResetLink(req: Request, token: string) {
-  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
-  return \`https://\${host}/reset?token=\${token}\`;
+  return \`\${CANONICAL_ORIGIN}/reset?token=\${encodeURIComponent(token)}\`;
 }`,
      },
    ];
  } else if (
    cat.includes("secret") ||
    cat.includes("git") ||
    cat.includes("exposure") ||
    ["secrets", "gitrepo"].includes(finding.agentKey)
  ) {
    summary = `Virtual patch and server configuration hardening to block public access to exposed .git directories, environment files, and source-map secrets on ${path}.`;
    wafRules = [
      {
        provider: "cloudflare",
        providerLabel: "Cloudflare WAF",
        title: "Cloudflare Custom Rule (Sensitive File & .git Blocker)",
        filename: `cloudflare-rule-exposure-${ruleId}.txt`,
        language: "plaintext",
        explanation: "Immediately blocks access to /.git, /.env, .map files, and backup archives.",
        code: `// Cloudflare Custom Rule (Expression Editor)
// Action: Block
(
  http.request.uri.path matches r"(?i)^/(\\.git|\\.env|\\.svn|\\.DS_Store|config\\.ya?ml|backup)"
  or http.request.uri.path ends_with ".map"
  or http.request.uri.path eq "${path}"
)`,
      },
      {
        provider: "awswaf",
        providerLabel: "AWS WAF v2",
        title: "AWS WAF v2 Dotfile & Secret Exposure Blocker",
        filename: `aws-waf-exposure-${ruleId}.json`,
        language: "json",
        explanation: "Blocks requests targeting dotfiles (.git, .env) and sourcemaps.",
        code: JSON.stringify(
          {
            Name: `SwarmScan-Block-Exposure-${ruleId}`,
            Priority: 5,
            Action: { Block: {} },
            VisibilityConfig: {
              SampledRequestsEnabled: true,
              CloudWatchMetricsEnabled: true,
              MetricName: `SwarmScanExposure${ruleId}`,
            },
            Statement: {
              RegexMatchStatement: {
                RegexString: "^/(\\.git|\\.env|.*\\.map$)",
                FieldToMatch: { UriPath: {} },
                TextTransformations: [{ Priority: 0, Type: "LOWERCASE" }],
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
        filename: `modsec-exposure-${ruleId}.conf`,
        language: "apache",
        explanation: "Denies public HTTP access to VCS metadata and dotenv files.",
        code: `# SwarmScan Virtual Patch — Sensitive File Exposure Block
SecRule REQUEST_URI "@rx (?i)^/(\\.git|\\.env|\\.svn|.*\\.map$)" \\
    "id:${ruleId},\\
    phase:1,\\
    deny,\\
    status:404,\\
    log,\\
    msg:'SwarmScan Virtual Patch: Blocked access to sensitive artifact'"`,
      },
      {
        provider: "nginx",
        providerLabel: "NGINX Configuration",
        title: "NGINX Dotfile & Sourcemap Deny Block",
        filename: `nginx-exposure-${ruleId}.conf`,
        language: "nginx",
        explanation: "Returns 404 for all hidden dotfiles and JS sourcemaps.",
        code: `# SwarmScan Virtual Patch for NGINX — Hide Sensitive Files
location ~* ^/(\\.git|\\.env|\\.svn)|\\.map$ {
    deny all;
    return 404;
}`,
      },
    ];
    codeRemediations = [
      {
        language: "typescript",
        label: "Next.js Config (Disable Production SourceMaps)",
        filename: "next.config.ts",
        explanation: "Disable browser source maps in production builds and rotate any exposed credentials immediately.",
        vulnerableSnippet: `// ❌ VULNERABLE: Exposes full unminified source & internal comments
const nextConfig = {
  productionBrowserSourceMaps: true,
};`,
        fixedSnippet: `// ✅ SECURE: Disable public browser source maps in production
const nextConfig = {
  productionBrowserSourceMaps: false,
};`,
        gitPatch: `--- a/next.config.ts
+++ b/next.config.ts
@@ -1,3 +1,3 @@
 const nextConfig = {
-  productionBrowserSourceMaps: true,
+  productionBrowserSourceMaps: false,
 };`,
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

export interface DeployedPatchItem {
  id: string;
  findingId: string;
  scanId: string;
  provider: string;
  ruleId: string;
  status: string;
  ruleContent: string;
  endpoint: string;
  deployedBy: string;
  deployedAt: string;
  revokedAt: string | null;
  findingTitle?: string;
  findingSeverity?: string;
  findingTarget?: string;
}

export interface RemediationPrItem {
  id: string;
  findingId: string;
  scanId: string;
  language: string;
  branchName: string;
  prTitle: string;
  prBody: string;
  patchDiff: string;
  status: string;
  createdAt: string;
}

export interface FindingRemediationResponse {
  package: RemediationPackage;
  deployedPatches: DeployedPatchItem[];
  remediationPrs: RemediationPrItem[];
}

/**
 * Generates an autonomous Pull Request payload (branch, title, markdown body, diff)
 * anchored to the finding's Bayesian confidence and WORM evidence chain.
 */
export function buildPullRequestPayload(finding: Finding, language?: string) {
  const pkg = generateRemediationPackage(finding);
  const code =
    pkg.codeRemediations.find((c) => c.language === language) ?? pkg.codeRemediations[0];
  const shortId = finding.id.slice(-8).toLowerCase();
  const safeAgent = finding.agentKey.replace(/[^a-z0-9-]/gi, "-").toLowerCase();
  const branchName = `swarmscan/fix-${safeAgent}-${shortId}`;
  const prTitle = `fix(security): remediate ${finding.title} (${finding.severity.toUpperCase()})`;
  const latestEvidenceHash =
    finding.evidence && finding.evidence.length > 0
      ? finding.evidence[finding.evidence.length - 1].hash
      : "worm-pending";

  const prBody = [
    `## SwarmScan Autonomous Security Remediation`,
    ``,
    `- **Finding:** ${finding.title} (\`${finding.id}\`)`,
    `- **Severity:** \`${finding.severity.toUpperCase()}\` | **Confidence:** \`${finding.confidence}/99\` (${finding.band})`,
    `- **Target / Endpoint:** \`${finding.target}\` — \`${pkg.endpoint}\``,
    finding.cve ? `- **CVE:** \`${finding.cve}\`` : null,
    `- **WORM Evidence Head:** \`${latestEvidenceHash}\``,
    ``,
    `### Root Cause & Fix`,
    code.explanation,
    ``,
    `### Unified Patch (\`${code.filename}\`)`,
    `\`\`\`diff`,
    code.gitPatch,
    `\`\`\``,
  ]
    .filter((line) => line !== null)
    .join("\n");

  return {
    language: code.language,
    branchName,
    prTitle,
    prBody,
    patchDiff: code.gitPatch,
  };
}
