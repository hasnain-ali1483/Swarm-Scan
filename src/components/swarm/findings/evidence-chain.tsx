"use client";

// ─── Evidence chain: ordered vertical ledger of a finding's evidence ─────────
// Each item: sequence node, kind badge + LR chip, pretty-printed JSON content,
// hash / prevHash with hover copy buttons, PII redaction notice.

import { motion } from "framer-motion";
import { ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, formatHash, timeAgo } from "@/lib/swarm/format";
import { type EvidenceItem } from "@/lib/swarm/types";
import { CopyButton } from "./copy-button";
import { evidenceKindMeta } from "./evidence-kinds";
import { prettyContent } from "./browser-utils";

function EvidenceRow({ item, index, total }: { item: EvidenceItem; index: number; total: number }) {
  const meta = evidenceKindMeta(item.kind);
  const redacted = item.content.includes("[REDACTED]");

  return (
    <motion.li
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.25, delay: index * 0.05 }}
      className="relative pl-12"
    >
      {/* connector to the next item */}
      {index < total - 1 ? (
        <span className="absolute bottom-0 left-4 top-10 w-px bg-zinc-800" aria-hidden />
      ) : null}
      {/* sequence node */}
      <span
        className="absolute left-0 top-0 flex h-8 w-8 items-center justify-center rounded-full border border-zinc-700 bg-zinc-900 font-mono text-[11px] text-zinc-400"
        aria-label={`Evidence sequence ${item.sequence}`}
      >
        {item.sequence}
      </span>

      <div className="min-w-0 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className={cn("px-1.5 py-0 text-[10px]", meta.badge)}>
            {meta.label}
          </Badge>
          <Badge variant="outline" className="border-zinc-700/70 bg-zinc-900/50 px-1.5 py-0 font-mono text-[10px] text-zinc-400">
            LR {item.lr.toFixed(1)}
          </Badge>
          {redacted ? (
            <Badge variant="outline" className="gap-1 border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0 text-[10px] text-emerald-400">
              <ShieldCheck className="h-3 w-3" aria-hidden />
              PII auto-redacted
            </Badge>
          ) : null}
          <span className="ml-auto text-[11px] text-zinc-500" title={new Date(item.createdAt).toISOString()}>
            {timeAgo(item.createdAt)}
          </span>
        </div>

        <pre className="swarm-scroll max-h-44 overflow-auto rounded-md border border-zinc-800 bg-zinc-950/80 p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
          {prettyContent(item.content)}
        </pre>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-zinc-500">
          <span className="group/hash flex items-center gap-1">
            <span aria-hidden>hash</span>
            <span className="text-zinc-400" title={item.hash}>
              {formatHash(item.hash, 12, 8)}
            </span>
            <CopyButton value={item.hash} toastLabel="Hash" className="opacity-0 transition-opacity group-hover/hash:opacity-100 focus-visible:opacity-100" />
          </span>
          <span className="group/prev flex items-center gap-1">
            <span aria-hidden>prev</span>
            <span className="text-zinc-400" title={item.prevHash}>
              {item.prevHash ? formatHash(item.prevHash, 12, 8) : "—"}
            </span>
            {item.prevHash ? (
              <CopyButton value={item.prevHash} toastLabel="Previous hash" className="opacity-0 transition-opacity group-hover/prev:opacity-100 focus-visible:opacity-100" />
            ) : null}
          </span>
        </div>
      </div>
    </motion.li>
  );
}

export function EvidenceChain({ evidence }: { evidence: EvidenceItem[] }) {
  const sorted = [...evidence].sort((a, b) => a.sequence - b.sequence);

  return (
    <Card className="gap-4">
      <CardHeader className="pb-0">
        <CardTitle className="flex items-center gap-2 text-sm">
          Evidence Chain
          <Badge variant="outline" className="border-zinc-700/70 bg-zinc-900/50 font-mono text-[10px] text-zinc-400">
            {sorted.length} {sorted.length === 1 ? "item" : "items"}
          </Badge>
        </CardTitle>
        <CardDescription className="text-xs">
          WORM-appended records in verification order — every entry is hash-chained into the
          evidence ledger.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {sorted.length === 0 ? (
          <p className="rounded-md border border-dashed px-4 py-8 text-center text-xs text-muted-foreground">
            No evidence records attached to this finding.
          </p>
        ) : (
          <ol className="space-y-5">
            {sorted.map((item, i) => (
              <EvidenceRow key={item.id} item={item} index={i} total={sorted.length} />
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}
