"use client";

// ─── Supply-chain summary strip for the Agent Registry (Task 10-b) ──────────
// "15/15 releases signed · 1 quarantined · SLSA L3" + the quarantined-hotfix
// alert with an Inspect dialog (failing verification checklist).

import { useState } from "react";
import { motion } from "framer-motion";
import { FileSignature, Lock, ShieldX } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { roleCan } from "@/lib/swarm/access-roles";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { cn, timeAgo } from "@/lib/swarm/format";
import { useBundleVerify, useSigning } from "./use-signing";
import { VerifyChecklist } from "./verify-checklist";

export function SigningSummary() {
  const { data } = useSigning();
  const verify = useBundleVerify();
  const actingRole = useSwarmUi((s) => s.actingRole);
  const canVerify = roleCan(actingRole, "signing:verify");
  const [inspectOpen, setInspectOpen] = useState(false);

  if (!data) return null;
  const { summary, bundles } = data;
  const quarantined = bundles.filter((b) => b.status !== "signed");

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-2"
    >
      {/* summary line */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-800 bg-card/50 px-3.5 py-2.5">
        <FileSignature className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
        <span className="text-xs font-medium text-zinc-200">Supply chain</span>
        <Badge
          variant="outline"
          className="gap-1 border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[10px] text-emerald-400"
          title="Every catalog release carries a Sigstore bundle: ed25519 signature, Fulcio cert, Rekor entry, SLSA L3 provenance"
        >
          {summary.signed}/{summary.signed} releases signed
        </Badge>
        <Badge
          variant="outline"
          className="border-primary/30 bg-primary/10 px-1.5 text-[10px] text-primary"
          title="Build level — hermetic, bit-identical rebuilds"
        >
          SLSA {summary.slsaLevel}
        </Badge>
        {summary.quarantined > 0 ? (
          <Badge
            variant="outline"
            className="gap-1 border-red-500/40 bg-red-500/10 px-1.5 text-[10px] text-red-400"
          >
            {summary.quarantined} quarantined
          </Badge>
        ) : null}
        {summary.lastVerifiedAt ? (
          <span className="ml-auto font-mono text-[10px] text-zinc-500">
            last verified {timeAgo(summary.lastVerifiedAt)}
          </span>
        ) : null}
      </div>

      {/* quarantined alert */}
      {quarantined.map((b) => (
        <div
          key={b.releaseTag}
          className={cn(
            "flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-lg border border-red-500/25 bg-red-500/[0.04] px-3.5 py-2.5"
          )}
          role="alert"
        >
          <div className="flex min-w-0 items-start gap-2.5">
            <ShieldX className="mt-0.5 h-4 w-4 shrink-0 text-red-400" aria-hidden />
            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <code className="font-mono text-xs font-medium text-red-300">{b.releaseTag}</code>
                <span className="text-[11px] text-zinc-400">registry quarantined — deploy refused</span>
              </div>
              <p className="mt-0.5 line-clamp-2 text-[10.5px] leading-snug text-zinc-400" title={b.note}>
                {b.note}
              </p>
            </div>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setInspectOpen(true)}
            className="h-7 shrink-0 gap-1.5 border-red-500/30 text-[11px] text-red-400 hover:bg-red-500/10 hover:text-red-400"
          >
            Inspect bundle
          </Button>
        </div>
      ))}

      <Dialog open={inspectOpen} onOpenChange={setInspectOpen}>
        <DialogContent className="max-h-[85vh] overflow-y-auto swarm-scroll bg-zinc-950/95 sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm">
              <ShieldX className="h-4 w-4 text-red-400" aria-hidden />
              Quarantined bundle
            </DialogTitle>
            <DialogDescription className="text-xs">
              Verification of a bundle pushed outside the release pipeline.
            </DialogDescription>
          </DialogHeader>
          {quarantined[0] ? (
            <div className="space-y-3 py-1">
              <div className="space-y-1 rounded-md border border-zinc-800 bg-zinc-900/40 p-3 font-mono text-[11px]">
                <div className="text-zinc-500">
                  release <span className="text-zinc-200">{quarantined[0].releaseTag}</span>
                </div>
                <div className="text-zinc-500">
                  hash <span className="break-all text-zinc-300">{quarantined[0].bundleHash}</span>
                </div>
                <div className="text-zinc-500">
                  size <span className="text-zinc-300">{quarantined[0].sizeBytes.toLocaleString()} bytes</span>
                </div>
                <div className="text-zinc-500">
                  signature <span className="text-red-400">none</span> · certificate{" "}
                  <span className="text-red-400">none</span> · provenance <span className="text-red-400">none</span>
                </div>
              </div>
              <p className="rounded-md border border-red-500/30 bg-red-500/[0.06] p-2.5 text-[11px] leading-relaxed text-red-300">
                {quarantined[0].note}
              </p>
              <div className="flex justify-end">
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={!canVerify || verify.isPending}
                  onClick={() =>
                    verify.mutate({ agentKey: quarantined[0].agentKey, releaseTag: quarantined[0].releaseTag })
                  }
                  className="h-7 gap-1.5 text-[11px]"
                  title={
                    canVerify
                      ? "Attempt verification — this bundle will fail at the certificate step"
                      : `signing:verify denied for ${actingRole} — switch the acting role in Access Control`
                  }
                >
                  {!canVerify && <Lock className="h-3.5 w-3.5" aria-hidden />}
                  {verify.isPending ? "Verifying…" : "Attempt verification"}
                </Button>
              </div>
              {verify.data ? <VerifyChecklist steps={verify.data.steps} verifying={false} /> : null}
              {verify.isPending ? <VerifyChecklist steps={[]} verifying /> : null}
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
