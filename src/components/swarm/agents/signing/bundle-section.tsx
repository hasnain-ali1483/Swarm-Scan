"use client";

// ─── Supply-chain section for an agent release (Task 10-b) ──────────────────
// Rendered inside the agent detail dialog: Sigstore bundle metadata (ed25519
// signature, Fulcio cert, Rekor entry, SLSA L3 provenance) + a Verify button
// that runs the checklist. Gated by the signing:verify permission.

import { Lock, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { roleCan } from "@/lib/swarm/access-roles";
import { useSwarmUi } from "@/lib/swarm/ui-store";
import { cn, timeAgo } from "@/lib/swarm/format";
import { useBundleVerify, useSigning } from "./use-signing";
import { VerifyChecklist } from "./verify-checklist";

function Row({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5 sm:flex-row sm:items-baseline sm:gap-3">
      <span className="w-36 shrink-0 font-mono text-[10px] uppercase tracking-wider text-zinc-600">
        {label}
      </span>
      <span
        className={cn("min-w-0 break-all text-[11px] text-zinc-300", mono && "font-mono")}
        title={value}
      >
        {value}
      </span>
    </div>
  );
}

export function BundleSection({ agentKey, releaseTag }: { agentKey: string; releaseTag: string }) {
  const { data } = useSigning();
  const verify = useBundleVerify();
  const actingRole = useSwarmUi((s) => s.actingRole);
  const canVerify = roleCan(actingRole, "signing:verify");

  const bundle = data?.bundles.find((b) => b.releaseTag === releaseTag);
  if (!bundle) return null;

  const signed = bundle.status === "signed";

  return (
    <section
      aria-label="Supply chain — signed release bundle"
      className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-900/40 p-3"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className={cn("h-4 w-4", signed ? "text-emerald-400" : "text-red-400")} aria-hidden />
          <span className="text-xs font-semibold text-zinc-100">Supply chain</span>
          <Badge
            variant="outline"
            className={cn(
              "gap-1 px-1.5 py-0 text-[9px] uppercase tracking-wider",
              signed
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                : "border-red-500/40 bg-red-500/10 text-red-400"
            )}
          >
            {signed ? "signed · SLSA L3" : "quarantined"}
          </Badge>
        </div>
        <Button
          size="sm"
          variant={signed ? "outline" : "destructive"}
          disabled={!canVerify || verify.isPending}
          onClick={() => verify.mutate({ agentKey: bundle.agentKey, releaseTag: bundle.releaseTag })}
          className="h-7 gap-1.5 text-[11px]"
          title={
            canVerify
              ? signed
                ? "Run the Sigstore/SLSA verification checklist"
                : "Attempt verification — this bundle will fail"
              : `signing:verify denied for ${actingRole} — switch the acting role in Access Control`
          }
        >
          {!canVerify && <Lock className="h-3.5 w-3.5" aria-hidden />}
          {verify.isPending ? "Verifying…" : signed ? "Verify signature" : "Attempt verification"}
        </Button>
      </div>

      {bundle.note ? (
        <p className="rounded-md border border-red-500/30 bg-red-500/[0.06] p-2.5 text-[11px] leading-relaxed text-red-300">
          {bundle.note}
        </p>
      ) : null}

      <div className="space-y-1.5">
        <Row label="release" value={bundle.releaseTag} />
        <Row label="bundle hash" value={bundle.bundleHash} />
        <Row label="size" value={`${bundle.sizeBytes.toLocaleString()} bytes`} />
        {signed ? (
          <>
            <Row label="signed" value={`${timeAgo(bundle.signedAt!)} · ${new Date(bundle.signedAt!).toLocaleString()}`} mono={false} />
            <Row label="signature" value={`${bundle.signature!.algorithm} · ${bundle.signature!.sigHex.slice(0, 48)}…`} />
            <Row label="cert subject" value={bundle.certificate!.subject} />
            <Row label="cert issuer" value={bundle.certificate!.issuer} />
            <Row label="cert validity" value={`${new Date(bundle.certificate!.validFrom).toLocaleDateString()} → ${new Date(bundle.certificate!.validTo).toLocaleDateString()}`} mono={false} />
            <Row label="rekor entry" value={`index ${bundle.tlog!.logIndex.toLocaleString()} · root ${bundle.tlog!.rootHash.slice(0, 24)}…`} />
            <Row label="materials" value={bundle.provenance!.materials.map((m) => m.uri).join(" · ")} mono={false} />
            <Row label="reproducible" value={bundle.provenance!.reproducible ? "yes — hermetic build, bit-identical rebuilds" : "no"} mono={false} />
          </>
        ) : null}
      </div>

      {verify.data ? <VerifyChecklist steps={verify.data.steps} verifying={false} /> : null}
      {verify.isPending ? <VerifyChecklist steps={[]} verifying /> : null}
    </section>
  );
}
