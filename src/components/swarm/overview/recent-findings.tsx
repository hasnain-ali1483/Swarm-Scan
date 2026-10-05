"use client";

// ─── Recent findings card (Overview row 3b) ──────────────────────────────────

import { ArrowRight, Siren } from "lucide-react";
import {
  Button,
} from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { BAND_STYLES, SEVERITY_STYLES, cn, timeAgo } from "@/lib/swarm/format";
import type { Finding } from "@/lib/swarm/types";

export function RecentFindings({ findings }: { findings: Finding[] }) {
  const setView = useSwarmUi((s) => s.setView);
  const openFinding = useSwarmUi((s) => s.openFinding);

  const open = (f: Finding) => {
    setView("findings");
    openFinding(f.id);
  };

  return (
    <Card className="h-full gap-2 rounded-xl px-4 py-4 sm:px-5">
      <CardHeader className="px-0">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Siren className="h-4 w-4 text-primary" aria-hidden />
          Recent Findings
        </CardTitle>
        <CardDescription className="text-xs">
          Latest emissions from the agent swarm
        </CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        <div className="max-h-[420px] overflow-y-auto swarm-scroll pr-1">
          {findings.length === 0 ? (
            <div className="py-8 text-center">
              <p className="font-mono text-xs text-muted-foreground">
                no findings emitted yet
              </p>
              <p className="mt-1 text-[11px] text-zinc-600">
                Launch a scan to populate the evidence ledger
              </p>
            </div>
          ) : (
            <ul className="space-y-0.5">
              {findings.map((f) => {
                const sev = SEVERITY_STYLES[f.severity];
                return (
                  <li key={f.id}>
                    <button
                      type="button"
                      onClick={() => open(f)}
                      className="group grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 rounded-md px-2 py-2 text-left transition-colors hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                      aria-label={`Open finding: ${f.title} (${sev.label}, confidence ${f.confidence})`}
                    >
                      <span
                        className={cn("h-2 w-2 shrink-0 rounded-full", sev.dot)}
                        aria-hidden
                      />
                      <span className="min-w-0">
                        <span className="block truncate text-[13px] font-medium text-zinc-200 group-hover:text-foreground">
                          {f.title}
                        </span>
                        <span className="block truncate font-mono text-[11px] text-muted-foreground">
                          {f.target}
                        </span>
                      </span>
                      <span className="flex shrink-0 flex-col items-end gap-1">
                        <span
                          className={cn(
                            "rounded border px-1.5 py-px font-mono text-[10px] font-semibold",
                            BAND_STYLES[f.band].badge
                          )}
                          title={`Confidence ${f.confidence}/99 — ${BAND_STYLES[f.band].hint}`}
                        >
                          {f.confidence}% conf
                        </span>
                        <span className="text-[10px] text-muted-foreground">
                          {timeAgo(f.createdAt)}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </CardContent>
      <CardFooter className="px-0 pb-0">
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto gap-1 text-primary hover:text-primary"
          onClick={() => setView("findings")}
        >
          View all findings
          <ArrowRight className="h-3.5 w-3.5" aria-hidden />
        </Button>
      </CardFooter>
    </Card>
  );
}
