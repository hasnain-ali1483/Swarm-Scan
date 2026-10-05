"use client";

// ─── PoC card: reproduction plan with copy-to-clipboard ──────────────────────

import { FlaskConical } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { CopyButton } from "./copy-button";

export function PocCard({ pocScript }: { pocScript: string | null }) {
  return (
    <Card className="gap-4">
      <CardHeader className="pb-0">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FlaskConical className="h-4 w-4 text-primary" aria-hidden />
          Reproduction Plan
        </CardTitle>
        <CardDescription className="text-xs">
          Deterministic PoC script — replayable against the same target and seed.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {pocScript ? (
          <div className="space-y-2">
            <div className="flex items-center justify-end">
              <CopyButton value={pocScript} toastLabel="Script" className="h-7 w-7" />
            </div>
            <pre className="swarm-scroll max-h-72 overflow-auto rounded-md border border-zinc-800 bg-zinc-950/80 p-3 font-mono text-xs leading-relaxed text-zinc-300">
              {pocScript}
            </pre>
            <Badge variant="outline" className="border-zinc-700/70 bg-zinc-900/50 font-mono text-[10px] text-zinc-500">
              policy-permitted · safe-class verification
            </Badge>
          </div>
        ) : (
          <p className="rounded-md border border-dashed px-4 py-8 text-center text-xs text-muted-foreground">
            No PoC plan generated
          </p>
        )}
      </CardContent>
    </Card>
  );
}
