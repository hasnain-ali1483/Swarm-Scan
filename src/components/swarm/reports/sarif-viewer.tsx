"use client";

// ─── SARIF 2.1 viewer — syntax-highlighted JSON ───────────────────────────────

import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

export function SarifViewer({ sarif }: { sarif: unknown }) {
  const text =
    typeof sarif === "string"
      ? sarif
      : sarif
        ? JSON.stringify(sarif, null, 2)
        : "{}";
  const bytes = new TextEncoder().encode(text).length;
  const results =
    typeof sarif === "object" && sarif !== null && "runs" in sarif
      ? ((sarif as { runs?: { results?: unknown[] }[] }).runs ?? []).reduce(
          (sum, run) => sum + (run.results?.length ?? 0),
          0
        )
      : null;

  return (
    <div className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950/70">
      <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-2">
        <span className="font-mono text-[11px] text-zinc-400">
          report.sarif · <span className="text-zinc-500">SARIF 2.1.0</span>
        </span>
        <span className="font-mono text-[10px] text-zinc-600">
          {results !== null && <span className="mr-3 text-zinc-500">{results} results</span>}
          {(bytes / 1024).toFixed(1)} KB
        </span>
      </div>
      <div className="max-h-[70vh] overflow-auto swarm-scroll" role="region" aria-label="SARIF JSON viewer">
        <SyntaxHighlighter
          language="json"
          style={oneDark}
          customStyle={{
            margin: 0,
            background: "transparent",
            fontSize: "11.5px",
            lineHeight: 1.55,
            padding: "0.875rem",
          }}
          codeTagProps={{
            style: { fontFamily: "var(--font-mono), ui-monospace, monospace" },
          }}
        >
          {text}
        </SyntaxHighlighter>
      </div>
    </div>
  );
}
