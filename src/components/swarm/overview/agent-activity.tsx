"use client";

// ─── Agent activity horizontal bars (Overview row 2c) ────────────────────────

import { motion } from "framer-motion";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BAND_STYLES, cn } from "@/lib/swarm/format";
import { bandOf, type OverviewResponse } from "@/lib/swarm/types";

export function AgentActivity({ agents }: { agents: OverviewResponse["agentActivity"] }) {
  const top = [...(agents ?? [])]
    .filter((a) => a.findings > 0)
    .sort((a, b) => b.findings - a.findings)
    .slice(0, 8);
  const max = Math.max(1, ...top.map((a) => a.findings));

  return (
    <Card className="h-full gap-3 rounded-xl px-4 py-4 sm:px-5">
      <CardHeader className="px-0">
        <CardTitle className="text-sm">Agent Activity</CardTitle>
        <CardDescription className="text-xs">
          Top agents by findings emitted · avg confidence
        </CardDescription>
      </CardHeader>
      <CardContent className="flex-1 px-0 pb-1">
        {top.length === 0 ? (
          <div className="flex h-[220px] items-center justify-center font-mono text-xs text-muted-foreground">
            no agent activity yet
          </div>
        ) : (
          <ul className="space-y-3">
            {top.map((a, i) => {
              const band = bandOf(a.avgConfidence);
              return (
                <motion.li
                  key={a.agentKey}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.25, delay: i * 0.04, ease: "easeOut" }}
                  className="grid grid-cols-[136px_1fr_auto] items-center gap-2.5 sm:grid-cols-[150px_1fr_auto]"
                >
                  <span
                    className="truncate font-mono text-[11px] text-zinc-300"
                    title={a.name}
                  >
                    {a.name}
                  </span>
                  <div
                    className="h-1.5 overflow-hidden rounded-full bg-muted"
                    role="img"
                    aria-label={`${a.name}: ${a.findings} findings, ${a.runs} runs`}
                  >
                    <motion.div
                      className="h-full rounded-full bg-primary/80"
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.max(4, (a.findings / max) * 100)}%` }}
                      transition={{ duration: 0.5, ease: "easeOut" }}
                    />
                  </div>
                  <span className="flex items-center gap-1.5 whitespace-nowrap">
                    <span className="font-mono text-xs font-semibold text-zinc-200">
                      {a.findings}
                    </span>
                    <span
                      className={cn(
                        "rounded border px-1.5 py-px font-mono text-[10px] font-medium",
                        BAND_STYLES[band].badge
                      )}
                      title={`avg confidence ${a.avgConfidence}% — ${BAND_STYLES[band].hint}`}
                    >
                      {Math.round(a.avgConfidence)}%
                    </span>
                  </span>
                </motion.li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
